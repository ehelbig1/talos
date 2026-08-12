//! Circuit breaker pattern for HTTP outbound requests.
//!
//! Prevents cascading failures when external APIs are down by temporarily
//! rejecting requests to failing hosts. Tracks failure rates per-host and
//! automatically recovers when the upstream service is healthy again.

use dashmap::DashMap;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

// ===========================================================================
// Prometheus counters — the breaker's only externally observable signal
// ===========================================================================
//
// ## Why these live HERE, in the worker, and not in `talos-metrics`
//
// `talos_circuit_breaker_opens_total` / `_blocks_total` were declared,
// constructed and registered in `talos-metrics` — the CONTROLLER's registry —
// from the day that crate was written, with ZERO increment sites anywhere in
// the workspace. They could not have had one: this breaker is a per-PROCESS
// `OnceLock` singleton living in the worker, and no controller-side code path
// observes it. Both series exported a flat 0 forever, on a platform where the
// breaker demonstrably opened (two `pa-meeting-prep` scheduled runs failed on
// it on 2026-08-10 and 2026-08-11, and 6 of the 8 failures in the #634 startup
// herd were the same breaker). An operator who queried the obvious metric name
// got `0` and would have concluded the breaker was not involved — a false
// negative dressed as data, which is worse than no metric at all.
//
// The fix keeps the NAMES (so the name an operator would guess is the name
// that carries the signal) and moves the producer to the process that owns the
// truth. The controller-side declarations are deleted in the same change, so
// exactly one process produces these series and there is no ambiguity about
// which `job` label is authoritative.
//
// A THIRD dead breaker-observability surface exists and is NOT addressed here:
// the Postgres table `circuit_breaker_metrics` (migration
// `20260329000000_new_modules_tables.sql`, plus an index on
// `(service_name, recorded_at)`). It is real, empty, and has no writer or
// reader anywhere in the workspace. Left alone deliberately — dropping a table
// is a migration, not an observability change — but recorded so the next person
// who greps `circuit_breaker` and finds it does not mistake it for a data
// source. All three surfaces failed the same way: something that LOOKS like it
// holds breaker history and holds nothing.
//
// ## What these counters cannot see
//
// **`wit_http::fetch` is the ONLY outbound-HTTP surface in this worker that
// touches the breaker at all.** Every other egress path neither consults it
// nor records an outcome, so both series are structurally blind to all of
// them. Enumerated rather than summarised, because the boundary is the thing
// an operator has to reason from:
//
//   * `wit_http::fetch_all`          (`host/http.rs`, batch HTTP)
//   * `wit_webhook::send`            (`host/webhook.rs`)
//   * `wit_graphql::execute`         (`host/graphql.rs`)
//   * `wit_http_stream`              (`host/http_stream.rs`)
//   * the four S3 operations         (`host/object_storage.rs`)
//   * the LLM tool-call client       (`host/llm_tools.rs`)
//   * the LLM + embedding clients    (`host/llm.rs`)
//   * the transactional-email client (`host/email.rs`)
//
// This was previously written as "structurally blind to batch HTTP", with the
// mitigation that no shipped module template calls `fetch_all`. That
// understated it in the direction that matters: `fetch_all` is indeed latent,
// but the LLM, webhook and GraphQL paths are on this platform's hot path
// TODAY, so the blindness is live, not latent. The honest statement is
// "everything except `wit_http::fetch`".
//
// Consequence for the runbook: a sentence of the form "if these are flat, the
// breaker is not involved" is sound only for modules whose egress goes
// through `wit_http::fetch`. It cannot exonerate — or implicate — any of the
// surfaces above. The alert description carries the same list.
//
// Extending the breaker to those surfaces is deliberately NOT done here: it
// is a design question, not a line, and it is argued at `fetch_all`'s
// `send()` in `host/http.rs`. This section is documentation of the existing
// boundary only.
//
// ## Why the `prometheus` crate here and not OTEL like the rest of `metrics.rs`
//
// The worker's `/metrics` endpoint renders `prometheus::gather()` — the
// DEFAULT registry — and `metrics::init_telemetry` wires the OTEL exporter
// into that same default registry. So a `prometheus`-crate collector
// registered here is exported by exactly the surface that already exists and
// is already scraped (`job="talos-worker"`), with no new plumbing. Three
// properties the OTEL path could not give us:
//
// 1. **No initialisation-order hazard.** An OTEL instrument built before
//    `set_meter_provider` binds to the no-op provider FOREVER. The breaker
//    fires from arbitrary points in a worker's life and from unit tests in
//    other modules of this crate, so a lazily-built OTEL instrument could be
//    permanently poisoned by whichever caller happened to be first.
// 2. **Not gated on `OTEL_METRICS_ENABLED`.** `RuntimeMetrics` is constructed
//    only when that env is true (default FALSE). A fail-closed control that
//    silently fails production jobs must not have its only signal behind an
//    optional flag. This is not hypothetical: `OTEL_METRICS_ENABLED` is set in
//    `docker-compose.yml` (dev, default `true`) and NOWHERE in the Helm chart,
//    so in a chart-deployed cluster it is unset and every `wasm_*` series is
//    dark. The counters below are ungated precisely so they do not inherit
//    that. NOTE the corollary for anyone citing the worker's existing
//    `/metrics` surface as evidence: the "105 `wasm_*` series live" figure is a
//    DEV-STACK observation and does not hold in production today. The argument
//    it supports — that a scraped `/metrics` endpoint already exists, so no new
//    worker→controller channel is needed — is unaffected, since the endpoint is
//    served and scraped regardless of that flag. Filed as its own finding in
//    `docs/backlog.md`; not fixed here.
// 3. **A concrete child counter is a single atomic add.** The five label
//    combinations below are resolved ONCE at init, so the increment on the
//    breaker's path is `IntCounter::inc()` — no map lookup, no lock. See the
//    "recorded outside the entry lock" note on `admit`.
//
// ## Label discipline
//
// Both label sets are CLOSED and enumerated by a Rust enum, so an unbounded
// value is not merely discouraged, it is unrepresentable. There is
// deliberately **no `host` label**: the host reaching the breaker is the
// authority of a guest-supplied URL. It is constrained by the module's
// declared `allowed_hosts`, but `allowed_hosts` is authored per module by any
// user who can compile one and may be the wildcard `*`, so the union over a
// shared worker's lifetime is unbounded. `cleanup()` exists in this very file
// because the breaker's own per-host map grows that way. Which host tripped is
// answered by the worker log (`host=` on every breaker transition), which is
// bounded by retention rather than by resident memory in the Prometheus TSDB.
//
// All five children are instantiated at registration, so an idle worker
// EXPORTS them at 0 rather than omitting them: `increase(...) > 0` is
// well-defined on a worker that has never tripped the breaker, instead of
// evaluating over an absent series. (Absent and zero are different — see the
// PromQL note in CLAUDE.md and `metrics::seed_zero_series`.)

/// How a circuit entered the `Open` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenTransition {
    /// `Closed` → `Open`: consecutive failures crossed the threshold.
    Opened,
    /// `HalfOpen` → `Open`: the trial requests did not meet the success rate.
    Reopened,
}

/// Why a request or retry was refused by the breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockReason {
    /// The circuit is `Open` and still inside its cooldown window; the HTTP
    /// request was rejected without being sent.
    ///
    /// NOTE this and [`Self::HalfOpenExhausted`] are INDISTINGUISHABLE
    /// downstream: `begin_request` returns `None` for both, and `host/http.rs`
    /// has a single `emit_network_failure` behind that one `None`, so both
    /// surface to the guest as `networkerror` and both stamp the execution
    /// error with `reason_class=circuit-open`. This label is the only thing
    /// that separates them — which is why it is a label and not a log line.
    Cooldown,
    /// The circuit is `HalfOpen` and its trial-request tokens are spent. Same
    /// downstream signature as [`Self::Cooldown`]; see the note there.
    HalfOpenExhausted,
    /// A job or pipeline step failed while one of its DECLARED hosts had an
    /// open circuit, so the breaker supplied the failure reason and skipped any
    /// remaining in-worker retries (`runtime.rs::circuit_open_error`). No HTTP
    /// request was attempted — this is the path whose controller-side error
    /// text reads "circuit open for host X".
    ///
    /// Do NOT read this as "a retry was skipped". Both call sites reach
    /// `circuit_open_error` BEFORE any retry-budget test — `runtime.rs`'s
    /// single-module site sits above `if attempt < retry_policy.max_attempts`,
    /// and the pipeline site is reached when `step.max_retries == 0` because
    /// `should_retry_pipeline_step` is guarded on `> 0`. Zero retries is the
    /// platform's documented default for state-changing and governance-world
    /// modules, so this arm routinely counts failures where no retry existed to
    /// skip and the gate changed only the error TEXT. What it does reliably
    /// mean is "this failure happened with the breaker already open for a host
    /// the job declared", which is what it is worth counting for.
    RetryGate,
}

struct BreakerMetrics {
    opened: prometheus::IntCounter,
    reopened: prometheus::IntCounter,
    block_cooldown: prometheus::IntCounter,
    block_half_open_exhausted: prometheus::IntCounter,
    block_retry_gate: prometheus::IntCounter,
}

impl BreakerMetrics {
    fn new() -> Self {
        let opens = prometheus::IntCounterVec::new(
            prometheus::Opts::new(
                "talos_circuit_breaker_opens_total",
                "Per-host outbound-HTTP circuit breaker transitions INTO the open state",
            ),
            &["transition"],
        )
        .expect("static circuit-breaker opens metric definition is valid");
        let blocks = prometheus::IntCounterVec::new(
            prometheus::Opts::new(
                "talos_circuit_breaker_blocks_total",
                "Outbound HTTP requests and in-worker retries refused by the circuit breaker",
            ),
            &["reason"],
        )
        .expect("static circuit-breaker blocks metric definition is valid");

        // Registration can only fail on a duplicate name, which a single
        // `LazyLock` initialiser cannot produce. Warn rather than panic: the
        // breaker's CONTROL behaviour must never be taken down by its own
        // observability. Unregistered children still increment, they are just
        // not exported.
        let registry = prometheus::default_registry();
        for c in [
            Box::new(opens.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(blocks.clone()),
        ] {
            if let Err(e) = registry.register(c) {
                tracing::warn!(
                    target: "talos_worker",
                    error = %e,
                    "failed to register circuit-breaker metrics; the breaker still \
                     functions but its counters will not be exported"
                );
            }
        }

        // Resolve every child ONCE. Two effects, both load-bearing: the
        // increment on the breaker path becomes a plain atomic add, and the
        // series exist at 0 on a worker that has never tripped the breaker.
        Self {
            opened: opens.with_label_values(&["opened"]),
            reopened: opens.with_label_values(&["reopened"]),
            block_cooldown: blocks.with_label_values(&["cooldown"]),
            block_half_open_exhausted: blocks.with_label_values(&["half_open_exhausted"]),
            block_retry_gate: blocks.with_label_values(&["retry_gate"]),
        }
    }

    fn record_open(&self, transition: OpenTransition) {
        match transition {
            OpenTransition::Opened => self.opened.inc(),
            OpenTransition::Reopened => self.reopened.inc(),
        }
    }

    fn record_block(&self, reason: BlockReason) {
        match reason {
            BlockReason::Cooldown => self.block_cooldown.inc(),
            BlockReason::HalfOpenExhausted => self.block_half_open_exhausted.inc(),
            BlockReason::RetryGate => self.block_retry_gate.inc(),
        }
    }
}

static BREAKER_METRICS: LazyLock<BreakerMetrics> = LazyLock::new(BreakerMetrics::new);

/// Force the breaker's counters into existence so an idle worker exports all
/// five series at 0.
///
/// Called from [`crate::metrics::init_telemetry`], i.e. once at worker
/// startup, before any job has run. Without it the first export would omit
/// these series entirely until the breaker first tripped — and an alert of the
/// shape `increase(...) > 0` over an ABSENT series matches nothing, so the
/// detector would be silent on exactly the worker that had never been observed
/// to trip. Idempotent.
pub fn seed_circuit_breaker_series() {
    LazyLock::force(&BREAKER_METRICS);
}

/// Count a job / pipeline-step fast-fail attributed to an already-open circuit.
///
/// The single chokepoint is `runtime.rs::circuit_open_error`, through which
/// both fast-fail return sites pass. This is a DISTINCT event from a rejected
/// HTTP request (`BlockReason::Cooldown`): no request is attempted, and it is
/// the path whose failure text reaches the controller as "circuit open for
/// host X". Keeping the two apart is the difference between an operator
/// knowing the breaker rejected a CALL and knowing it decided the outcome of a
/// whole job.
///
/// See [`BlockReason::RetryGate`] for why this must not be described as "a
/// retry that was skipped" — the gate is evaluated before the retry budget is
/// consulted, so it also counts jobs that had no retries to skip.
///
/// Because the increment is here, only real refusals may call
/// `circuit_open_error`. Anything wanting the message text uses
/// `runtime::circuit_open_message`.
pub(crate) fn record_retry_gate_block() {
    BREAKER_METRICS.record_block(BlockReason::RetryGate);
}

/// Global circuit breaker instance.
/// Initialized on first access with default configuration.
static GLOBAL_CIRCUIT_BREAKER: OnceLock<HttpCircuitBreaker> = OnceLock::new();

/// Get the global circuit breaker instance.
/// Initializes on first call with default configuration.
pub fn get_global_circuit_breaker() -> &'static HttpCircuitBreaker {
    GLOBAL_CIRCUIT_BREAKER.get_or_init(|| {
        let config = CircuitBreakerConfig::from_env();
        HttpCircuitBreaker::new(config)
    })
}

/// MCP-580: spawn a periodic-cleanup task for the global breaker. Call
/// once at worker startup. The breaker's per-host `records` DashMap
/// grows monotonically with distinct hosts seen — `cleanup` was
/// defined but had zero callers, so a worker that's fetched many
/// hosts (or a misbehaving module that fetches from a long tail of
/// short-lived domains) would accumulate `CircuitRecord` entries
/// forever. Open / HalfOpen circuits are preserved by `cleanup` (we
/// want them remembered until they recover); only stale Closed
/// circuits with no recent activity get evicted. Default sweep
/// every 5 minutes with 30-minute max-age, configurable via
/// `CIRCUIT_BREAKER_CLEANUP_SECS` / `CIRCUIT_BREAKER_MAX_AGE_SECS`.
/// Idempotent — calling twice spawns two tasks (harmless but wasteful);
/// design assumes one call from main.
pub fn spawn_periodic_cleanup() {
    let interval_secs: u64 = std::env::var("CIRCUIT_BREAKER_CLEANUP_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n >= 30)
        .unwrap_or(300);
    let max_age_secs: u64 = std::env::var("CIRCUIT_BREAKER_MAX_AGE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n >= 60)
        .unwrap_or(1800);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        // The first tick fires immediately — skip it so we don't sweep
        // a freshly-empty map.
        interval.tick().await;
        loop {
            interval.tick().await;
            get_global_circuit_breaker().cleanup(Duration::from_secs(max_age_secs));
        }
    });
    tracing::info!(
        target: "talos_worker",
        event_kind = "circuit_breaker_cleanup_spawned",
        interval_secs,
        max_age_secs,
        "Circuit-breaker periodic cleanup task started"
    );
}

/// Configuration for the circuit breaker.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit.
    pub failure_threshold: u32,
    /// Duration the circuit stays open before allowing test requests.
    pub open_duration: Duration,
    /// Duration to track failures (failures older than this are ignored).
    pub failure_window: Duration,
    /// Success rate required in half-open state to close the circuit (0.0-1.0).
    pub success_rate_threshold: f64,
    /// Number of test requests to allow in half-open state.
    pub test_requests: u32,
}

impl CircuitBreakerConfig {
    /// Create configuration from environment variables.
    ///
    /// MCP-689 (2026-05-13): three numeric envs routed through
    /// `positive_env_or_default`. Pre-fix `=0` for any of them was
    /// silently destructive:
    /// - `CIRCUIT_BREAKER_FAILURE_THRESHOLD=0` — circuit opens after
    ///   zero failures = permanently open. Every outbound HTTP call
    ///   returns CircuitOpen.
    /// - `CIRCUIT_BREAKER_OPEN_DURATION_SECS=0` — circuit re-closes
    ///   immediately after opening; defeats the breaker entirely.
    /// - `CIRCUIT_BREAKER_FAILURE_WINDOW_SECS=0` — every failure
    ///   counts as already expired; failure count stays at zero;
    ///   circuit never opens.
    ///
    /// MCP-711 (2026-05-13): MCP-689 missed two more sites:
    /// - `CIRCUIT_BREAKER_TEST_REQUESTS=0` — `test_requests_remaining`
    ///   starts at 0 on HalfOpen entry, so `allow_request` returns
    ///   false for every test (line 231-234). With no test allowed,
    ///   no success/failure can be recorded, so the circuit can never
    ///   transition back to Closed. Effectively pins every previously-
    ///   tripped host into permanent rejection.
    /// - `CIRCUIT_BREAKER_SUCCESS_RATE` — out-of-range values (≤0,
    ///   ≥1, NaN, Inf) silently produce nonsense:
    ///   * `0.0` → circuit closes on the first HalfOpen test
    ///     regardless of outcome → success-rate check is bypassed,
    ///     defeats half of the breaker's purpose.
    ///   * `>1.0` or `NaN` → `success_rate >= threshold` is always
    ///     false → circuit re-opens after every HalfOpen cycle and
    ///     never closes, similar to the test_requests=0 trap.
    ///   * `<0.0` → `success_rate >= threshold` always true → closes
    ///     on first success regardless of test_failures count.
    ///   Same `=0`/out-of-range footgun class as MCP-665/MCP-689.
    ///   Clamp to `[0.0, 1.0]` and reject NaN/Inf — the only
    ///   meaningful operator values.
    pub fn from_env() -> Self {
        // MCP-711: clamp success-rate to [0.0, 1.0] and reject NaN/Inf.
        let success_rate_threshold = std::env::var("CIRCUIT_BREAKER_SUCCESS_RATE")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|n| n.is_finite() && (0.0..=1.0).contains(n))
            .unwrap_or_else(|| {
                // If env was set to a parseable but out-of-range value
                // (e.g. `1.5`, `NaN`, `-1`), the filter drops it and we
                // fall through to the default. Emit a WARN at config
                // time so operators see the clamp without waiting for
                // a circuit-breaker event to surface the issue.
                if let Ok(raw) = std::env::var("CIRCUIT_BREAKER_SUCCESS_RATE") {
                    if !raw.is_empty() {
                        tracing::warn!(
                            target: "talos_worker",
                            event_kind = "circuit_breaker_success_rate_substituted",
                            configured = %raw,
                            default = 0.8,
                            "CIRCUIT_BREAKER_SUCCESS_RATE is not a finite value in [0.0, 1.0]; \
                             substituting default 0.8"
                        );
                    }
                }
                0.8
            });
        Self {
            failure_threshold: talos_config::positive_env_or_default(
                "CIRCUIT_BREAKER_FAILURE_THRESHOLD",
                5u32,
            ),
            open_duration: Duration::from_secs(talos_config::positive_env_or_default(
                "CIRCUIT_BREAKER_OPEN_DURATION_SECS",
                30u64,
            )),
            failure_window: Duration::from_secs(talos_config::positive_env_or_default(
                "CIRCUIT_BREAKER_FAILURE_WINDOW_SECS",
                60u64,
            )),
            success_rate_threshold,
            // MCP-711: same `positive_env_or_default` treatment as the
            // three above. `=0` would stick every previously-tripped
            // host in permanent rejection.
            test_requests: talos_config::positive_env_or_default(
                "CIRCUIT_BREAKER_TEST_REQUESTS",
                3u32,
            ),
        }
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
            failure_window: Duration::from_secs(60),
            success_rate_threshold: 0.8,
            test_requests: 3,
        }
    }
}

// ===========================================================================
// What counts as a failure — the connectivity-vs-health decision (2026-08-12)
// ===========================================================================
//
// Read this before adding any new call to `record_failure`.
//
// ## The constraint that decides it: the breaker is HOST-KEYED and
// ## PROCESS-GLOBAL
//
// `GLOBAL_CIRCUIT_BREAKER` is one `OnceLock` per worker process, and its map
// is keyed by hostname and NOTHING else. A worker consumes jobs for every
// user, every actor and every workflow on the platform, so a circuit opened
// for `www.googleapis.com` refuses that host for ALL of them until it closes.
//
// That is defensible for a TRANSPORT failure: a failed TCP connect, a TLS
// handshake error or a DNS failure is a property of the host and the network
// path, which every tenant genuinely shares. It is NOT defensible for an HTTP
// status, because no status code is a property of the host alone:
//
//   * 401 / 403 — a property of ONE user's credential. The expired-OAuth-token
//     case is not hypothetical; it is the routine steady state of this
//     platform's Google integrations. If 4xx opened circuits, one user's stale
//     refresh token would take `www.googleapis.com` away from every other
//     user's calendar, Gmail and Drive workflows. A reliability feature would
//     have manufactured a cross-tenant outage.
//   * 404 / 400 / 422 — a property of one REQUEST (or one module's bug).
//   * 429 — a property of one user's QUOTA. On Google APIs
//     `userRateLimitExceeded` is per-user; backing off is right for the user
//     who is being limited, and the breaker cannot express "for that user"
//     because it is not keyed by user. Blocking everyone else converts A's
//     rate limit into B's outage.
//   * 5xx — the closest to a host property, and still not one: a 500 can be
//     provoked by one tenant's payload while the host serves everyone else
//     perfectly.
//
// ## The decision
//
// **An HTTP status can NEVER open a circuit.** The Closed→Open transition
// stays keyed to reqwest transport errors, so the population that can be
// newly blocked by a status is EMPTY.
//
// **A 5xx, and ONLY a 5xx, can fail a half-open recovery trial.** See
// [`status_fails_recovery_trial`]. That decision can only keep an
// ALREADY-OPEN circuit open for one more cooldown; it can never block anyone
// who was not already blocked, and without it the breaker had a real defect:
// a host answering nothing but `503` returned `Ok(resp)` to every trial,
// scored a 100% success rate, and CLOSED the circuit against an upstream that
// was serving nothing. Resuming full traffic onto a host that just told you it
// is failing is the exact outcome the breaker exists to prevent.
//
// ## Why 429 is NOT a trial failure (reversed 2026-08-12, review; do not
// ## re-litigate without re-reading this paragraph and the arithmetic in it)
//
// The first version of this change failed a trial on `5xx || 429`. That
// applied the tenancy argument above to OPENING and then abandoned it at
// CLOSING, which is the same mistake one step later in the state machine.
//
// The arithmetic is what makes it not merely inelegant. Defaults are
// `test_requests = 3` and `success_rate_threshold = 0.8`, so a period closes
// only on 3/3 — 2/3 is 0.667 and re-opens. A 429 is ROUTINE on this
// platform's Google integrations and is per-CALLER by construction
// (`userRateLimitExceeded`), so ONE rate-limited tenant taking one trial
// token was enough to re-open the circuit for EVERY tenant, one cooldown at a
// time, for as long as that tenant kept probing. Before the change a 429
// counted as a trial success, the circuit closed, everyone proceeded, and the
// rate-limited tenant kept getting their own 429s — correctly isolated,
// because a per-user quota is exactly the kind of fact this shared,
// host-keyed structure must not learn.
//
// "It can prolong an outage, it cannot start one" is true and thin: to a
// tenant who is blocked, a circuit that never closes is indistinguishable
// from one that opened. 429 therefore gets the same treatment as every other
// 4xx — it PASSES the trial, because it proves the host is alive and serving,
// which is the only question a trial is entitled to ask.
//
// The asymmetry is enforced STRUCTURALLY, not by comment: the status is only
// consulted when the admission consumed a half-open trial token, and the
// resulting failure is routed to [`HttpCircuitBreaker::record_trial_failure`],
// which refuses to act on any state other than `HalfOpen` in the same epoch
// and never touches `consecutive_failures`. There is no code path by which a
// status reaches the open decision.
//
// ## The residual cross-tenant tail with 429 removed, stated accurately
//
// It is smaller and it is NOT zero, and the arithmetic above still applies:
// one 5xx anywhere in a three-trial period guarantees that period ends in a
// re-open (2/3 = 0.667 < 0.8). It does not re-open on the spot — the rate
// check runs only once all three verdicts are in — but the period is decided
// the moment the first 5xx lands. So if user A's payload specifically draws a
// 500 from a host that serves user B perfectly, and A's request happens to
// take a trial token, B stays blocked for another `open_duration`.
//
// That is ACCEPTED, for three reasons, and it is the whole of the remaining
// tail:
//
//   1. Direction. A 5xx is the host asserting its own failure. Of the
//      statuses, it is the only one whose subject is the server, so it is the
//      only one whose fail-safe direction is legitimately toward blocking. A
//      429's subject is the CALLER, and a 4xx's is the request — for those,
//      blocking is a category error, which is why they now all pass.
//   2. It is bounded and self-clearing. The circuit was already open when
//      this began; each cooldown is `open_duration` (30 s default) and
//      re-admits a fresh full set of trial tokens. Nothing latches. The
//      pre-change alternative is strictly worse for B, because it CLOSES the
//      circuit and sends B's traffic to a host that is answering 503.
//   3. Widening the tolerance is a THRESHOLD change, not a semantics one.
//      Making one 5xx survivable means `test_requests` up or
//      `success_rate_threshold` down, which changes how every trial verdict
//      is reached — including the transport-driven ones this change does not
//      touch. That is a separate, measurable decision and is deliberately not
//      bundled here.
//
// ## Fail-safe direction of each new path
//
//   * Trial gets 5xx → trial FAILS → circuit stays open. Fails toward
//     BLOCKING work on a host that answered with a server error. Right,
//     because the trial's question is "has it recovered?" and the host itself
//     answered no. Bounded by `open_duration`; self-clearing.
//   * Trial gets 4xx, INCLUDING 429 → trial SUCCEEDS → circuit may close.
//     Fails toward ADMITTING work. Right, and not a compromise: a 401 or a
//     429 proves the host is alive and serving, which is precisely what the
//     trial asks. The credential or quota problem behind it is per-user and
//     must not be encoded in shared state.
//   * A reqwest BUILDER error (an invalid header name or value the guest
//     authored) → NO evidence recorded either way. Fails toward ADMITTING
//     work. Right, because the request never left the process, so there is no
//     evidence about the host in either direction — and the pre-change
//     behaviour, counting it as a host failure, was a live cross-tenant
//     vector: five `fetch` calls carrying a malformed header name would open
//     `www.googleapis.com` for every tenant on the worker without a single
//     packet being sent.
//
// ## What is deliberately NOT changed
//
// A response body that fails MID-TRANSFER (`bytes_stream` yields an `Err`
// after the headers arrived) is still recorded as a SUCCESS, because the
// outcome is settled at the send. That is a genuine transport failure and
// arguably should count; changing it would widen the OPEN decision, which is
// the surface this change is deliberately keeping still. Left as-is and
// recorded here.

/// Does this HTTP status mean a half-open recovery trial FAILED?
///
/// **Consulted only for the trial verdict — never for the Closed→Open
/// decision.** See the "connectivity-vs-health" note above for the full
/// argument, in particular why every 4xx is deliberately absent (a 401 is one
/// user's credential, and this breaker is shared by every user on the worker).
///
/// * `5xx` — the host answered and admitted its own failure. The only status
///   whose SUBJECT is the server, and therefore the only one whose fail-safe
///   direction is legitimately toward blocking. Not evidence of recovery.
/// * everything else, including `429` — the host is alive and serving, which
///   is the only question a recovery trial is entitled to ask.
///
/// **`429` is deliberately NOT here, and was removed in review on 2026-08-12
/// after the first version of this function included it.** A 429 is
/// per-CALLER by construction (`userRateLimitExceeded` on Google APIs is
/// per-user) and routine on this platform. With `test_requests = 3` and
/// `success_rate_threshold = 0.8` a period closes only on 3/3, so a single
/// 429 taken by ONE rate-limited tenant re-opened the circuit for EVERY
/// tenant, one cooldown at a time, indefinitely. Adding it back re-creates a
/// cross-tenant outage out of one tenant's routine quota error. If you are
/// here to add a status, the test that will stop you is
/// `a_429_trial_closes_the_circuit_because_the_quota_is_one_tenants`.
fn status_fails_recovery_trial(status: u16) -> bool {
    status >= 500
}

/// State of a circuit breaker for a specific host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitState {
    /// Circuit is closed, requests are allowed.
    Closed,
    /// Circuit is open, requests are rejected.
    Open,
    /// Circuit is half-open, allowing test requests.
    HalfOpen,
}

/// Record of circuit breaker state for a specific host.
struct CircuitRecord {
    state: CircuitState,
    consecutive_failures: u32,
    last_failure: Instant,
    last_state_change: Instant,
    test_requests_remaining: u32,
    test_successes: u32,
    test_failures: u32,
}

impl CircuitRecord {
    fn new() -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            last_failure: Instant::now(),
            last_state_change: Instant::now(),
            test_requests_remaining: 0,
            test_successes: 0,
            test_failures: 0,
        }
    }
}

/// Circuit breaker for HTTP outbound requests.
///
/// Tracks failures per-host and prevents requests to failing hosts.
/// Uses a three-state model: Closed -> Open -> HalfOpen -> Closed.
pub struct HttpCircuitBreaker {
    records: Arc<DashMap<String, CircuitRecord>>,
    config: CircuitBreakerConfig,
}

impl HttpCircuitBreaker {
    /// Create a new circuit breaker with the given configuration.
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            records: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Create a new circuit breaker with default configuration.
    pub fn new_default() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }

    /// Check if a request to the given host should be allowed.
    ///
    /// Returns `true` if the request should proceed, `false` if it should be rejected.
    ///
    /// # The 2026-08-11 11:35 stranding, and which way the causation runs
    ///
    /// Stated here because getting the direction wrong is what made the
    /// incident hard to read, and the wrong direction was asserted once in the
    /// change that added these counters.
    ///
    /// **Token EXHAUSTION caused the observed failure. The token LEAK is the
    /// consequence, not the cause.** In order:
    ///
    /// ```text
    /// 08-10 13:45:29  #634's startup herd trips www.googleapis.com   → Open
    /// +30 s           → HalfOpen, 3 trial tokens (HalfOpen has NO time bound)
    /// 08-11 11:12:09  pa-daily-brief spends 2, both succeed; 2 < 3 so the
    ///                 circuit STAYS HalfOpen                         → 1 left
    /// 08-11 11:35:10  cal_work + cal_personal fan out in parallel. cal_work
    ///                 takes the LAST token; cal_personal is REFUSED
    ///                 (`half_open_exhausted`) — this is the visible failure
    /// 08-11 11:35:10.5288  cal_personal is cancelled before recording an
    ///                 outcome, leaking its token                     → 0
    /// … → www.googleapis.com stranded at HalfOpen-with-0-tokens until the
    ///     23:06 container recreate cleared the process-local map.
    /// ```
    ///
    /// So the leak explains the 11½ hours of stranding AFTER 11:35; it does not
    /// explain 11:35 itself, which was simply the third token being spent.
    ///
    /// **This reconstruction is CONSISTENT with the evidence, not FORCED by
    /// it.** The competing hypothesis — the host was already at 0 tokens from
    /// an EARLIER leak, and both nodes were refused — is tilted against by
    /// `execution_events`, which holds a `node_failed` for `cal_work` and none
    /// for `cal_personal`: under the competing story both should have failed.
    /// That is not conclusive. Sibling cancellation could have suppressed
    /// `cal_personal`'s event, which would make an originally SYMMETRIC block
    /// look asymmetric — the same cancellation the leak turns on. The two are
    /// separable only by `talos_circuit_breaker_blocks_total{reason=...}`,
    /// which is why it now exists.
    ///
    /// The decision is taken while the per-host DashMap entry is held; the
    /// metric is recorded AFTER that guard drops. Nothing was added inside the
    /// critical section, so the lock-free-in-the-common-case shape of this
    /// path is unchanged — and the allowed path (a Closed circuit, i.e. every
    /// request on a healthy worker) records nothing at all.
    ///
    /// # This is the RAW primitive and it LEAKS. Production must not call it.
    ///
    /// An admission taken here is never repaid. In `HalfOpen` that is the
    /// stranding bug above: the caller owes an outcome and nothing in the type
    /// system says so. Production goes through [`Self::begin_request`], which
    /// returns a [`RequestPermit`] that repays the token on `Drop`.
    ///
    /// Retained, test-only, for exactly one reason: it is the PRE-FIX
    /// behaviour, and
    /// `strand_reproduction_the_raw_primitive_leaks_and_never_recovers` uses
    /// it to reproduce the 2026-08-11 stranding on demand. A fix whose baseline
    /// cannot be reproduced is unfalsifiable. `#[cfg(test)]` is what makes
    /// "no production caller can leak a token" a COMPILE-TIME property rather
    /// than a review convention.
    #[cfg(test)]
    pub(crate) fn allow_request(&self, host: &str) -> bool {
        match self.admit(host) {
            Ok(_) => true,
            Err(reason) => {
                BREAKER_METRICS.record_block(reason);
                false
            }
        }
    }

    /// Ask for admission and take the accompanying obligation with it.
    ///
    /// `None` = refused (the block metric has already been recorded, exactly
    /// as the pre-permit code did). `Some(permit)` = admitted; the caller MUST
    /// settle the permit with the outcome, and if it does not — by an early
    /// return, a `?`, a panic, or the whole future being dropped mid-flight —
    /// `Drop` repays any half-open trial token that the admission spent.
    ///
    /// This is the ONLY admission path production has. See
    /// `allow_request` (test-only, so deliberately NOT linked — an intra-doc
    /// link from a public item to a `#[cfg(test)]` target does not resolve
    /// under `cargo doc`) for why the raw primitive cannot be called from
    /// production.
    pub fn begin_request(&self, host: &str) -> Option<RequestPermit<'_>> {
        match self.admit(host) {
            Ok(trial_epoch) => Some(RequestPermit {
                breaker: self,
                host: host.to_string(),
                trial_epoch,
                settled: false,
            }),
            Err(reason) => {
                BREAKER_METRICS.record_block(reason);
                None
            }
        }
    }

    /// The admission decision itself, with no metric side effect.
    ///
    /// * `Ok(None)` — admitted with NO trial token spent (the Closed circuit,
    ///   i.e. every request on a healthy worker). Nothing is owed.
    /// * `Ok(Some(epoch))` — admitted by spending one `HalfOpen` trial token.
    ///   `epoch` is the `last_state_change` of the half-open period the token
    ///   came from, so a repayment arriving after the circuit has moved on can
    ///   be recognised and dropped instead of crediting a later period.
    /// * `Err(reason)` — refused.
    fn admit(&self, host: &str) -> Result<Option<Instant>, BlockReason> {
        let now = Instant::now();
        let mut entry = self
            .records
            .entry(host.to_string())
            .or_insert_with(CircuitRecord::new);
        let record = entry.value_mut();

        // Check if we should transition from Open to HalfOpen
        if record.state == CircuitState::Open {
            if now.duration_since(record.last_state_change) >= self.config.open_duration {
                record.state = CircuitState::HalfOpen;
                record.test_requests_remaining = self.config.test_requests;
                record.test_successes = 0;
                record.test_failures = 0;
                record.last_state_change = now;
                tracing::info!(host = %host, "Circuit breaker entering half-open state");
            } else {
                // Circuit is still open, reject the request
                tracing::warn!(
                    host = %host,
                    remaining_secs = (record.last_state_change + self.config.open_duration)
                        .saturating_duration_since(now)
                        .as_secs(),
                    "Circuit breaker rejecting request"
                );
                return Err(BlockReason::Cooldown);
            }
        }

        // In half-open state, only allow test requests
        if record.state == CircuitState::HalfOpen {
            if record.test_requests_remaining == 0 {
                // No more test requests allowed, reject
                return Err(BlockReason::HalfOpenExhausted);
            }
            record.test_requests_remaining -= 1;
            return Ok(Some(record.last_state_change));
        }

        Ok(None)
    }

    /// Return an unused half-open trial token to the pool.
    ///
    /// The third outcome the two-state model never had: the trial did not
    /// CONCLUDE. Neither `test_successes` nor `test_failures` moves — an
    /// abandoned probe is not evidence that the host is healthy (which would
    /// let a leak CLOSE a circuit against a dead host) and not evidence that
    /// it is sick (which would let a guest-side rejection RE-OPEN one against
    /// a healthy host, and would hand any guest that can provoke an early
    /// return a lever on shared state). It is evidence of nothing, so the only
    /// correct move is to put the token back and let a real request answer the
    /// question.
    ///
    /// Epoch-gated: a repayment is credited only if the circuit is STILL in
    /// the same half-open period the token was taken from. A permit that
    /// outlives its period (the circuit re-opened, or closed and re-opened,
    /// while the request was in flight) is dropped on the floor rather than
    /// granting a fourth trial in a three-trial period.
    ///
    /// No metric, and the entry guard is dropped before returning, so this
    /// holds no DashMap shard across anything.
    fn repay_trial_token(&self, host: &str, epoch: Instant) {
        let Some(mut entry) = self.records.get_mut(host) else {
            return;
        };
        let record = entry.value_mut();
        if record.state != CircuitState::HalfOpen || record.last_state_change != epoch {
            return;
        }
        record.test_requests_remaining = record
            .test_requests_remaining
            .saturating_add(1)
            .min(self.config.test_requests);
    }

    /// Record a half-open trial that FAILED on the strength of its HTTP
    /// status (a 5xx), rather than on a transport error.
    ///
    /// This is the only place an HTTP status can move breaker state in the
    /// failing direction, and it is deliberately unable to influence the OPEN
    /// decision:
    ///
    /// * it no-ops unless the circuit is still `HalfOpen` in the same period
    ///   the trial token came from — so a status arriving after the circuit
    ///   closed cannot be replayed into the Closed-state failure counter;
    /// * it never touches `consecutive_failures`, which is the only field the
    ///   Closed→Open transition reads.
    ///
    /// Net: a 5xx can prolong an outage for one cooldown, and can never start
    /// one. That is the whole cross-tenant safety argument, held up by control
    /// flow instead of by a comment. See the "connectivity-vs-health" note at
    /// the top of this file.
    ///
    /// The epoch gate is NOT unique to the failing side: its twin
    /// [`Self::record_trial_success`] carries the identical gate, added in
    /// review on 2026-08-12. Before that the success side was ungated (via
    /// the bare `record_success`) and a straggler from a dead half-open
    /// period credited the CURRENT period's `test_successes` — so this
    /// doc-comment's "structural guarantee" framing described only half of
    /// the structure. Keep the two in lockstep.
    ///
    /// The gate covers the two STATUS paths and NOT
    /// [`RequestPermit::settle_transport_failure`], which is deliberate and
    /// argued there.
    fn record_trial_failure(&self, host: &str, epoch: Instant) {
        let opened = {
            let now = Instant::now();
            let Some(mut entry) = self.records.get_mut(host) else {
                return;
            };
            let record = entry.value_mut();
            if record.state != CircuitState::HalfOpen || record.last_state_change != epoch {
                return;
            }

            record.test_failures += 1;
            let mut opened: Option<OpenTransition> = None;
            let total_tests = record.test_successes + record.test_failures;
            if total_tests >= self.config.test_requests {
                let success_rate = record.test_successes as f64 / total_tests as f64;
                if success_rate < self.config.success_rate_threshold {
                    record.state = CircuitState::Open;
                    record.last_state_change = now;
                    tracing::warn!(
                        host = %host,
                        success_rate = %success_rate,
                        "Circuit breaker re-opened — the recovery trial got a 5xx, which \
                         is the host asserting its own failure and is not evidence of \
                         recovery"
                    );
                    opened = Some(OpenTransition::Reopened);
                }
            }
            opened
        };

        if let Some(transition) = opened {
            BREAKER_METRICS.record_open(transition);
        }
    }

    /// Record a half-open trial that SUCCEEDED, scoped to the period its
    /// token came from.
    ///
    /// The epoch-gated twin of [`Self::record_trial_failure`], added in review
    /// on 2026-08-12 because the failure side was gated and the success side
    /// was not. The asymmetry was reachable: a permit whose request outlived
    /// its half-open period — client timeouts run to 120 s, cooldown is 30 s —
    /// settled through the ungated `record_success`, whose `HalfOpen` arm
    /// credited whatever period was current, tally `(0,0) → (1,0)`. A
    /// straggler could therefore help CLOSE a period that had not earned it.
    ///
    /// The correction is small on purpose: a stale success is discarded, not
    /// redirected. It is evidence from a window that has already been decided,
    /// and the only alternatives — crediting the current period (the bug) or
    /// re-deriving a Closed-state effect from it — either restore the defect
    /// or invent an outcome the request never had.
    ///
    /// Two of the three other states are genuinely unchanged, which is why
    /// this is a narrow fix rather than a rewrite: settling into an `Open`
    /// circuit hit `record_success`'s explicit no-op arm, and settling into
    /// the SAME half-open period behaves exactly as before.
    ///
    /// The third does change, in the same direction and worth stating rather
    /// than glossing: a straggler settling into a circuit that has since
    /// CLOSED used to reach `record_success`'s Closed arm and zero
    /// `consecutive_failures`, and now does nothing. Those failures may have
    /// accumulated AFTER the close, from live requests — so the old behaviour
    /// let evidence from a decided period suppress a current failure streak,
    /// and delaying an open on the strength of a stale success is not a
    /// property worth keeping. Losing it is an improvement, not a cost.
    fn record_trial_success(&self, host: &str, epoch: Instant) {
        let opened = {
            let now = Instant::now();
            let Some(mut entry) = self.records.get_mut(host) else {
                return;
            };
            let record = entry.value_mut();
            if record.state != CircuitState::HalfOpen || record.last_state_change != epoch {
                return;
            }

            record.test_successes += 1;
            let mut opened: Option<OpenTransition> = None;
            let total_tests = record.test_successes + record.test_failures;
            if total_tests >= self.config.test_requests {
                let success_rate = record.test_successes as f64 / total_tests as f64;
                if success_rate >= self.config.success_rate_threshold {
                    record.state = CircuitState::Closed;
                    record.consecutive_failures = 0;
                    record.last_state_change = now;
                    tracing::info!(
                        host = %host,
                        success_rate = %success_rate,
                        "Circuit breaker closed"
                    );
                } else {
                    // The period concluded ON a success and still missed the
                    // bar — one 5xx earlier in a 3-trial / 0.8 period is
                    // enough, and that period was decided the moment the 5xx
                    // landed. Re-open.
                    record.state = CircuitState::Open;
                    record.last_state_change = now;
                    tracing::warn!(
                        host = %host,
                        success_rate = %success_rate,
                        "Circuit breaker re-opened — the recovery trial did not meet the \
                         success-rate threshold"
                    );
                    opened = Some(OpenTransition::Reopened);
                }
            }
            opened
        };

        if let Some(transition) = opened {
            BREAKER_METRICS.record_open(transition);
        }
    }

    /// Record a successful request to the given host.
    ///
    /// Metric recorded after the entry guard drops (see the note on
    /// `admit`). The overwhelmingly common case — a success on a Closed
    /// circuit — takes no metric path at all.
    ///
    /// NOTE this is the UNGATED primitive: its `HalfOpen` arm credits whatever
    /// half-open period is current, with no epoch check. Production reaches it
    /// only for admissions that spent NO trial token (a Closed circuit);
    /// trial settlements go through [`Self::record_trial_success`]. Kept
    /// `pub` for the pre-permit two-state tests that drive the state machine
    /// directly.
    pub fn record_success(&self, host: &str) {
        let opened = {
            let now = Instant::now();
            let mut entry = self
                .records
                .entry(host.to_string())
                .or_insert_with(CircuitRecord::new);
            let record = entry.value_mut();

            let mut opened: Option<OpenTransition> = None;

            match record.state {
                CircuitState::Closed => {
                    // Reset failure counter on success
                    if record.consecutive_failures > 0 {
                        record.consecutive_failures = 0;
                        tracing::debug!(host = %host, "Circuit breaker: reset failure counter");
                    }
                }
                CircuitState::HalfOpen => {
                    record.test_successes += 1;
                    // Check if we should close the circuit
                    let total_tests = record.test_successes + record.test_failures;
                    if total_tests >= self.config.test_requests {
                        let success_rate = record.test_successes as f64 / total_tests as f64;
                        if success_rate >= self.config.success_rate_threshold {
                            record.state = CircuitState::Closed;
                            record.consecutive_failures = 0;
                            record.last_state_change = now;
                            tracing::info!(
                                host = %host,
                                success_rate = %success_rate,
                                "Circuit breaker closed"
                            );
                        } else {
                            // Not enough successes, go back to open
                            record.state = CircuitState::Open;
                            record.last_state_change = now;
                            tracing::warn!(
                                host = %host,
                                success_rate = %success_rate,
                                "Circuit breaker re-opened due to low success rate"
                            );
                            opened = Some(OpenTransition::Reopened);
                        }
                    }
                }
                CircuitState::Open => {
                    // Shouldn't happen, but just in case
                }
            }

            opened
        };

        if let Some(transition) = opened {
            BREAKER_METRICS.record_open(transition);
        }
    }

    /// Record a failed request to the given host.
    ///
    /// Metric recorded after the entry guard drops (see the note on `admit`).
    pub fn record_failure(&self, host: &str) {
        let opened = {
            let now = Instant::now();
            let mut entry = self
                .records
                .entry(host.to_string())
                .or_insert_with(CircuitRecord::new);
            let record = entry.value_mut();

            // Reset if outside the failure window
            if now.duration_since(record.last_failure) >= self.config.failure_window {
                record.consecutive_failures = 0;
            }

            record.last_failure = now;

            let mut opened: Option<OpenTransition> = None;

            match record.state {
                CircuitState::Closed => {
                    record.consecutive_failures += 1;
                    if record.consecutive_failures >= self.config.failure_threshold {
                        record.state = CircuitState::Open;
                        record.last_state_change = now;
                        tracing::warn!(
                            host = %host,
                            consecutive_failures = record.consecutive_failures,
                            "Circuit breaker opened"
                        );
                        opened = Some(OpenTransition::Opened);
                    }
                }
                CircuitState::HalfOpen => {
                    record.test_failures += 1;
                    // Check if we should re-open
                    let total_tests = record.test_successes + record.test_failures;
                    if total_tests >= self.config.test_requests {
                        let success_rate = record.test_successes as f64 / total_tests as f64;
                        if success_rate < self.config.success_rate_threshold {
                            record.state = CircuitState::Open;
                            record.last_state_change = now;
                            tracing::warn!(
                                host = %host,
                                success_rate = %success_rate,
                                "Circuit breaker re-opened"
                            );
                            opened = Some(OpenTransition::Reopened);
                        }
                    }
                }
                CircuitState::Open => {
                    // Already open, nothing to do
                }
            }

            opened
        };

        if let Some(transition) = opened {
            BREAKER_METRICS.record_open(transition);
        }
    }

    /// Read-only peek: is the circuit for `host` currently OPEN and
    /// still within its cooldown window?
    ///
    /// Distinct from [`Self::begin_request`], which MUTATES (drives the
    /// Open→HalfOpen transition and the half-open test-token accounting).
    /// `is_open` never mutates — it is the retry-decision gate: when a
    /// host's circuit is OPEN and cooling down, in-worker retries against
    /// it are pointless (the outage is sustained), so the retry loop
    /// short-circuits and fails fast instead of burning its budget on a
    /// host we already know is down.
    ///
    /// Returns `false` once the cooldown has elapsed (the circuit is
    /// ready for a half-open trial) so the next real request still gets
    /// its single probe via `begin_request`, and `false` for a host with
    /// no record or a Closed/HalfOpen circuit.
    pub fn is_open(&self, host: &str) -> bool {
        self.records
            .get(host)
            .map(|r| {
                r.state == CircuitState::Open
                    && Instant::now().duration_since(r.last_state_change)
                        < self.config.open_duration
            })
            .unwrap_or(false)
    }

    /// Get the current state of a circuit breaker for a host (for debugging/metrics).
    pub fn get_state(&self, host: &str) -> Option<String> {
        self.records.get(host).map(|r| match r.state {
            CircuitState::Closed => "closed".to_string(),
            CircuitState::Open => "open".to_string(),
            CircuitState::HalfOpen => "half_open".to_string(),
        })
    }

    /// Clean up old entries to prevent memory growth.
    /// Call periodically (e.g., every 5 minutes).
    pub fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        self.records.retain(|host, record| {
            let retain = match record.state {
                CircuitState::Closed => {
                    // Keep closed circuits if they've had activity recently
                    now.duration_since(record.last_failure) < max_age
                        || now.duration_since(record.last_state_change) < max_age
                }
                CircuitState::Open | CircuitState::HalfOpen => {
                    // Always keep open/half-open circuits
                    true
                }
            };
            if !retain {
                tracing::debug!(host = %host, "Removing stale circuit breaker record");
            }
            retain
        });
    }

    /// Put a host straight into `HalfOpen` with `tokens` trial tokens.
    ///
    /// Test-only. The alternative for a test that needs a half-open circuit is
    /// to trip it and then sleep past `open_duration`, which on the GLOBAL
    /// breaker means the default 30 s (its config is read from the environment
    /// once, under a `OnceLock`, so a test cannot shorten it without racing
    /// every other test in the binary).
    #[cfg(test)]
    pub(crate) fn force_half_open(&self, host: &str, tokens: u32) {
        let mut entry = self
            .records
            .entry(host.to_string())
            .or_insert_with(CircuitRecord::new);
        let record = entry.value_mut();
        record.state = CircuitState::HalfOpen;
        record.test_requests_remaining = tokens;
        record.test_successes = 0;
        record.test_failures = 0;
        record.last_state_change = Instant::now();
    }

    /// Unspent half-open trial tokens for `host`. Test-only: this is the
    /// quantity the stranding bug destroyed, so it is the quantity the fix's
    /// tests have to be able to read.
    #[cfg(test)]
    pub(crate) fn trial_tokens_remaining(&self, host: &str) -> Option<u32> {
        self.records.get(host).map(|r| r.test_requests_remaining)
    }

    /// `(test_successes, test_failures)` for `host`. Test-only. An abandoned
    /// trial must move NEITHER, which is a different assertion from "the token
    /// came back".
    #[cfg(test)]
    pub(crate) fn trial_tally(&self, host: &str) -> Option<(u32, u32)> {
        self.records
            .get(host)
            .map(|r| (r.test_successes, r.test_failures))
    }

    /// The Closed-state failure counter — the ONLY field the Closed→Open
    /// transition reads. Test-only, and the assertion target for "an HTTP
    /// status can never open a circuit".
    #[cfg(test)]
    pub(crate) fn consecutive_failures(&self, host: &str) -> Option<u32> {
        self.records.get(host).map(|r| r.consecutive_failures)
    }
}

/// An outstanding admission from [`HttpCircuitBreaker::begin_request`], and
/// the obligation that comes with it.
///
/// # Why this is a guard and not four `return` sites
///
/// The stranding fixed here (`www.googleapis.com`, 2026-08-11 11:35 →
/// 23:06) came from `allow_request` spending a half-open trial token roughly
/// 180 lines above the `send()` that repaid it, with four statement exits and
/// two `.await` points in between. Patching those six sites would have been
/// correct on the day and wrong on the next day somebody adds a seventh — and
/// two of the six are not patchable that way at all: a `?` is not a `return`
/// (the previous inventory, built by grepping for `return`, missed the one
/// that fires deterministically in production), and a dropped future does not
/// execute any statement to patch.
///
/// A `Drop` impl is the only construction that covers a cancelled future, and
/// it covers every future early exit for free, including ones not yet written
/// and including a panic unwinding through the middle. That property — "you
/// cannot add a leaking path to this function" — is the deliverable; repaying
/// the specific tokens is just what it does.
///
/// # Cost on the healthy path
///
/// A permit issued against a CLOSED circuit — every request on a healthy
/// worker — carries `trial_epoch: None`, and its `Drop` is an `Option`
/// discriminant test that touches no map, takes no lock and emits no metric.
/// The only per-request cost added to the hot path is one `String` clone of
/// the host, alongside the one `allow_request` already made for the DashMap
/// entry key.
pub struct RequestPermit<'a> {
    breaker: &'a HttpCircuitBreaker,
    host: String,
    /// `Some(epoch)` iff this admission spent a half-open trial token, where
    /// `epoch` identifies the half-open period it came from.
    trial_epoch: Option<Instant>,
    settled: bool,
}

impl RequestPermit<'_> {
    /// The peer answered with `status`.
    ///
    /// On a CLOSED circuit this is a success unconditionally — byte-identical
    /// to the pre-change `record_success` on `Ok(resp)`, and deliberately so:
    /// letting a status reach the Closed→Open transition is the cross-tenant
    /// failure mode argued against at the top of this file.
    ///
    /// On a half-open TRIAL the status decides the verdict, via
    /// [`status_fails_recovery_trial`] — a 5xx fails it, everything else
    /// (including 429) passes it. **Both verdicts are EPOCH-GATED**: a trial
    /// settlement is credited only to the half-open period whose token this
    /// permit spent. A settlement that arrives after that period ended is
    /// discarded rather than applied to whatever period is current — which
    /// matters because the client timeout runs to 120 s against a 30 s
    /// cooldown, so a straggler outliving its period is a real window, not a
    /// theoretical one. The failing side has been gated since the permit
    /// existed; the SUCCEEDING side was gated in review on 2026-08-12, after
    /// it was found to credit the current period's `test_successes`.
    ///
    /// See [`HttpCircuitBreaker::record_trial_success`] /
    /// [`HttpCircuitBreaker::record_trial_failure`].
    pub fn settle_response(&mut self, status: u16) {
        if self.claim_settle() {
            return;
        }
        match self.trial_epoch {
            Some(epoch) if status_fails_recovery_trial(status) => {
                self.breaker.record_trial_failure(&self.host, epoch);
            }
            Some(epoch) => self.breaker.record_trial_success(&self.host, epoch),
            None => self.breaker.record_success(&self.host),
        }
    }

    /// The request failed in transport — connect, DNS, TLS, reset, or the
    /// client's own timeout. Evidence about the HOST, and the only kind of
    /// evidence allowed to open a circuit.
    ///
    /// # The one settle path that is still NOT epoch-gated, stated rather than
    /// # implied
    ///
    /// This routes to the ungated `record_failure`, so a straggler transport
    /// failure from a DEAD half-open period is counted against whatever period
    /// is current. That is the same shape as the success-side asymmetry closed
    /// on 2026-08-12, and it is left in place deliberately, for two reasons —
    /// not because it was missed:
    ///
    /// * `record_failure`'s `Closed` arm is the OPEN decision, and unlike a
    ///   status, a transport failure is genuine host evidence whenever it
    ///   arrives. Gating it would NARROW the open decision, which is the one
    ///   axis this area of the code is holding still so that post-deploy
    ///   movement in `opens_total{transition="opened"}` stays attributable.
    /// * It is pre-existing, not a regression: `record_failure` was equally
    ///   ungated before the permit existed.
    ///
    /// So "trial settlements are epoch-gated" is true of the two STATUS paths
    /// and not of this one. Note the fail-safe direction differs too — a
    /// misattributed transport failure fails toward BLOCKING, where the
    /// misattributed success it mirrors failed toward ADMITTING.
    pub fn settle_transport_failure(&mut self) {
        if self.claim_settle() {
            return;
        }
        self.breaker.record_failure(&self.host);
    }

    /// The request never left this process, so nothing was learned about the
    /// host in either direction.
    ///
    /// The caller for this is a reqwest BUILDER error: an invalid header name
    /// or value, which on this path is guest-authored. Before the permit
    /// existed those were fed to `record_failure`, which means five `fetch`
    /// calls carrying a malformed header name could open a shared,
    /// process-global circuit for a perfectly healthy host without emitting a
    /// packet. Settling as no-evidence repays the trial token and records
    /// neither outcome.
    ///
    /// # What this predicts for `opens_total{transition="opened"}`
    ///
    /// It should FALL. Stated here because the first version of the change
    /// that introduced this method predicted the opposite — it called the open
    /// decision "byte-identical", so any post-deploy movement in that counter
    /// was to be read as environmental. That is wrong for exactly this path:
    /// `record_failure`'s `Closed` arm is the sole emitter of `Opened`, and
    /// this method REMOVES a class of input (guest-authored builder errors)
    /// from it. A decline after deploy is a direct, expected consequence of
    /// this change and specifically not noise. Only the STATUS half of that
    /// change was open-decision-neutral.
    pub fn settle_no_evidence(&mut self) {
        if self.claim_settle() {
            return;
        }
        self.repay();
    }

    /// Take the permit's single settlement, returning `true` if it was
    /// already taken and the caller must do NOTHING.
    ///
    /// # Why `settled` is read and not merely written
    ///
    /// It used to be write-only: all three settle methods set it and only
    /// `Drop` read it, so a second settle recorded a SECOND outcome against
    /// the same request. That was not a hypothetical — the filed follow-up for
    /// moving the settle past the response body (`docs/backlog.md`) originally
    /// asserted "`RequestPermit::settled` already makes a second settle a
    /// no-op rather than a double count, so the mechanical risk is low", and
    /// then suggested the exact shape that double-settles: settle at the send
    /// error AND after the body loop. On a half-open trial that posts one
    /// success and one failure from a single probe, consumes two of the three
    /// slots, and — at the default 3 trials / 0.8 threshold — GUARANTEES a
    /// re-open at 2/3.
    ///
    /// A permit is one request and therefore one datapoint. Making the flag
    /// load-bearing is what turns that sentence from a convention into a
    /// property, so the trap cannot be walked into by a caller who believes
    /// the doc.
    fn claim_settle(&mut self) -> bool {
        let already = self.settled;
        self.settled = true;
        already
    }

    fn repay(&self) {
        if let Some(epoch) = self.trial_epoch {
            self.breaker.repay_trial_token(&self.host, epoch);
        }
    }
}

impl Drop for RequestPermit<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.repay();
        }
    }
}

impl Default for HttpCircuitBreaker {
    fn default() -> Self {
        Self::new_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_closed_to_open() {
        let cb = HttpCircuitBreaker::default();
        let host = "example.com";

        // Initially closed, requests allowed
        assert!(cb.allow_request(host));

        // Record 5 failures to trip the circuit
        for _ in 0..5 {
            cb.record_failure(host);
        }

        // Circuit should now be open, requests rejected
        assert!(!cb.allow_request(host));
    }

    #[test]
    fn test_circuit_breaker_open_to_half_open() {
        let config = CircuitBreakerConfig {
            open_duration: Duration::from_millis(10),
            ..Default::default()
        };
        let cb = HttpCircuitBreaker::new(config);
        let host = "example.com";

        // Trip the circuit
        for _ in 0..5 {
            cb.record_failure(host);
        }
        assert!(!cb.allow_request(host));

        // Wait for open duration
        std::thread::sleep(Duration::from_millis(20));

        // Should now be half-open, allowing test requests
        assert!(cb.allow_request(host));
        assert_eq!(cb.get_state(host), Some("half_open".to_string()));
    }

    #[test]
    fn test_circuit_breaker_half_open_to_closed() {
        let config = CircuitBreakerConfig {
            open_duration: Duration::from_millis(0),
            test_requests: 3,
            success_rate_threshold: 0.7,
            ..Default::default()
        };
        let cb = HttpCircuitBreaker::new(config);
        let host = "example.com";

        // Trip the circuit
        for _ in 0..5 {
            cb.record_failure(host);
        }

        // Should be half-open immediately (open_duration = 0)
        // Allow and record 3 successful test requests
        for _ in 0..3 {
            assert!(cb.allow_request(host));
            cb.record_success(host);
        }

        // Circuit should now be closed
        assert_eq!(cb.get_state(host), Some("closed".to_string()));
    }

    #[test]
    fn is_open_false_when_closed_or_unknown() {
        let cb = HttpCircuitBreaker::default();
        // Never-seen host has no record.
        assert!(!cb.is_open("unseen.example.com"));
        // A host with sub-threshold failures stays Closed → not open.
        let host = "example.com";
        cb.record_failure(host);
        assert!(!cb.is_open(host), "one failure must not open the circuit");
    }

    #[test]
    fn is_open_true_within_cooldown_then_false_after() {
        let config = CircuitBreakerConfig {
            open_duration: Duration::from_millis(30),
            ..Default::default()
        };
        let cb = HttpCircuitBreaker::new(config);
        let host = "down.example.com";

        // Trip the circuit (default threshold = 5).
        for _ in 0..5 {
            cb.record_failure(host);
        }
        // Within cooldown: is_open reports true and — crucially — does
        // NOT mutate state (unlike allow_request, which would transition
        // to HalfOpen once the cooldown elapses).
        assert!(cb.is_open(host));
        assert!(
            cb.is_open(host),
            "is_open must be idempotent / non-mutating"
        );
        assert_eq!(cb.get_state(host), Some("open".to_string()));

        // After the cooldown elapses, is_open reports false so the next
        // real request can take its half-open trial via allow_request.
        std::thread::sleep(Duration::from_millis(45));
        assert!(
            !cb.is_open(host),
            "past cooldown the breaker must permit a half-open trial"
        );
        // State is still Open until allow_request is called (is_open is a
        // pure peek), but the retry gate keys on is_open, not raw state.
        assert_eq!(cb.get_state(host), Some("open".to_string()));
    }

    #[test]
    fn is_open_false_in_half_open() {
        let config = CircuitBreakerConfig {
            open_duration: Duration::from_millis(0),
            ..Default::default()
        };
        let cb = HttpCircuitBreaker::new(config);
        let host = "recover.example.com";
        for _ in 0..5 {
            cb.record_failure(host);
        }
        // open_duration=0 → first allow_request transitions to HalfOpen.
        assert!(cb.allow_request(host));
        assert_eq!(cb.get_state(host), Some("half_open".to_string()));
        // A half-open circuit is under trial, not "open" for retry-gating.
        assert!(!cb.is_open(host));
    }

    /// MCP-711: CIRCUIT_BREAKER_TEST_REQUESTS=0 would pin every tripped
    /// host into permanent rejection because `test_requests_remaining`
    /// starts at 0 on HalfOpen entry, so `allow_request` returns false
    /// for every test → no success can be recorded → circuit never
    /// transitions back to Closed. Tripwire the fix.
    ///
    /// Uses `from_env` directly so the test exercises the same parse
    /// path production hits at boot. Env mutation is serialized via the
    /// test mutex (same pattern as talos-compilation::container tests).
    #[test]
    fn from_env_clamps_test_requests_zero_to_default() {
        let _g = env_lock_for_test();
        std::env::set_var("CIRCUIT_BREAKER_TEST_REQUESTS", "0");
        let cfg = CircuitBreakerConfig::from_env();
        std::env::remove_var("CIRCUIT_BREAKER_TEST_REQUESTS");
        assert_eq!(
            cfg.test_requests, 3,
            "test_requests=0 must be substituted with default 3 (positive_env_or_default contract)"
        );
    }

    /// MCP-711: NaN / out-of-range success-rate values silently produce
    /// nonsense before the fix. Confirm the clamp routes to the default.
    #[test]
    fn from_env_clamps_success_rate_out_of_range_to_default() {
        let _g = env_lock_for_test();
        for raw in ["1.5", "-0.1", "NaN", "Inf", "-Inf"] {
            std::env::set_var("CIRCUIT_BREAKER_SUCCESS_RATE", raw);
            let cfg = CircuitBreakerConfig::from_env();
            assert!(
                (cfg.success_rate_threshold - 0.8).abs() < f64::EPSILON,
                "success_rate={raw} must fall back to default 0.8, got {}",
                cfg.success_rate_threshold
            );
        }
        std::env::remove_var("CIRCUIT_BREAKER_SUCCESS_RATE");
    }

    /// MCP-711: an in-range success_rate must NOT be clamped. Locks in
    /// the boundary behavior so a future tightening of the predicate
    /// doesn't accidentally swallow legitimate operator config.
    #[test]
    fn from_env_honors_in_range_success_rate() {
        let _g = env_lock_for_test();
        for raw in ["0.0", "0.5", "1.0"] {
            std::env::set_var("CIRCUIT_BREAKER_SUCCESS_RATE", raw);
            let cfg = CircuitBreakerConfig::from_env();
            let expected: f64 = raw.parse().unwrap();
            assert!(
                (cfg.success_rate_threshold - expected).abs() < f64::EPSILON,
                "success_rate={raw} must be honored verbatim, got {}",
                cfg.success_rate_threshold
            );
        }
        std::env::remove_var("CIRCUIT_BREAKER_SUCCESS_RATE");
    }

    /// MCP-711: serialize env-var-touching tests inside this module so
    /// parallel test execution doesn't race `CIRCUIT_BREAKER_*` reads.
    /// Same pattern as `talos-compilation::container::env_lock` — module-
    /// local Mutex with poisoned-recovery.
    fn env_lock_for_test() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // =======================================================================
    // Metric wiring
    // =======================================================================

    /// Read one exported counter's value out of the rendered exposition.
    ///
    /// Deliberately parses the RENDERED TEXT rather than reading the
    /// `IntCounter` handle: the handle would go up even if the collector had
    /// failed to register, which is the exact failure mode that leaves an
    /// operator with a silent metric. Only the exposition proves the value
    /// reaches a scrape.
    ///
    /// PANICS when the series is absent or unparseable, and that is the point.
    /// This helper previously ended `.unwrap_or(0)` — the check-52 silent-
    /// default shape, inside the guard for a check-58 defect. A missing series
    /// is precisely the bug these tests exist to catch, and reading it as the
    /// number zero is how the original defect presented in production. Every
    /// caller seeds first (`seed_circuit_breaker_series` is idempotent), so
    /// absence here means the registration broke, not that nothing has happened
    /// yet.
    fn exported(metric: &str, label: &str, value: &str) -> u64 {
        seed_circuit_breaker_series();
        let text = crate::metrics::get_prometheus_metrics();
        let needle = format!("{metric}{{{label}=\"{value}\"");
        let line = text
            .lines()
            .find(|l| l.starts_with(&needle))
            .unwrap_or_else(|| {
                panic!(
                    "series {needle}...}} is ABSENT from the rendered exposition — the \
                     collector is not registered, so any alert over it is silent.\n{text}"
                )
            });
        let raw = line.rsplit(' ').next().unwrap_or_else(|| {
            panic!("exposition line for {needle}...}} has no value field: {line:?}")
        });
        raw.parse::<f64>()
            .unwrap_or_else(|e| panic!("value {raw:?} on line {line:?} is unparseable: {e}"))
            as u64
    }

    /// The whole point of the change: BOTH counters must move when the real
    /// breaker does the real thing.
    ///
    /// Before this change `talos_circuit_breaker_opens_total` and
    /// `talos_circuit_breaker_blocks_total` were declared and registered in
    /// `talos-metrics` (the CONTROLLER's registry) with zero increment sites
    /// anywhere in the workspace; both exported a flat 0 on a live stack whose
    /// breaker had demonstrably opened. A lint that only checks "is this field
    /// mutated somewhere" cannot catch that class — CLAUDE.md's own check-58
    /// notes say a wrapper nothing calls still reads as live. So this drives
    /// the PRODUCTION methods (`record_failure`, `begin_request`,
    /// `circuit_open_error`) and reads the RENDERED exposition.
    ///
    /// Uses strict before/after deltas rather than absolute values: the
    /// counters are process-global and the other tests in this binary trip
    /// breakers of their own in parallel. Counters are monotonic, so a
    /// concurrent test can only inflate the "after" — it can never make a
    /// genuinely-wired counter look unmoved, and it can never make an unwired
    /// one look moved from THIS test's own events.
    #[test]
    fn production_path_moves_both_counters() {
        const OPENS: &str = "talos_circuit_breaker_opens_total";
        const BLOCKS: &str = "talos_circuit_breaker_blocks_total";

        let before_opened = exported(OPENS, "transition", "opened");
        let before_cooldown = exported(BLOCKS, "reason", "cooldown");
        let before_retry_gate = exported(BLOCKS, "reason", "retry_gate");

        let cb = HttpCircuitBreaker::new(CircuitBreakerConfig {
            // Long enough that the reject below cannot race into HalfOpen.
            open_duration: Duration::from_secs(60),
            ..Default::default()
        });
        let host = "opens-probe.example.test";

        // Closed → Open: the `opened` transition.
        for _ in 0..5 {
            cb.record_failure(host);
        }
        // Open + inside cooldown: an HTTP request refused without being sent.
        assert!(
            cb.begin_request(host).is_none(),
            "circuit must be open after 5 failures"
        );
        // The job-level retry gate: no request attempted at all.
        let _ = crate::runtime::circuit_open_error(host);

        assert!(
            exported(OPENS, "transition", "opened") > before_opened,
            "{OPENS}{{transition=\"opened\"}} did not move across a real \
             Closed→Open transition — the counter is not wired to the breaker"
        );
        assert!(
            exported(BLOCKS, "reason", "cooldown") > before_cooldown,
            "{BLOCKS}{{reason=\"cooldown\"}} did not move across a real \
             in-cooldown request rejection"
        );
        assert!(
            exported(BLOCKS, "reason", "retry_gate") > before_retry_gate,
            "{BLOCKS}{{reason=\"retry_gate\"}} did not move across a real \
             retry-gate fast-fail — circuit_open_error is the chokepoint for \
             both fast-fail sites in runtime.rs"
        );
    }

    /// The remaining two label values, which the test above cannot reach:
    /// re-opening out of HalfOpen, and exhausting the HalfOpen trial tokens.
    ///
    /// These exist as separate label values because they are separate
    /// operator situations — "the host went down" versus "the host came back
    /// and immediately failed its trial again", which is a longer outage than
    /// the first open suggests.
    ///
    /// Note the exhaustion half is driven by holding permits CONCURRENTLY,
    /// which is the only way `half_open_exhausted` is reachable now that an
    /// unsettled permit repays its token on drop. Before 2026-08-12 it was
    /// also reachable by leaking, and a leaked token never came back — which
    /// is precisely why this arm firing steadily used to mean "stranded" and
    /// now means "in flight".
    #[test]
    fn half_open_reopen_and_token_exhaustion_move_their_own_labels() {
        const OPENS: &str = "talos_circuit_breaker_opens_total";
        const BLOCKS: &str = "talos_circuit_breaker_blocks_total";

        let before_reopened = exported(OPENS, "transition", "reopened");
        let before_exhausted = exported(BLOCKS, "reason", "half_open_exhausted");

        let cb = HttpCircuitBreaker::new(CircuitBreakerConfig {
            // Straight to HalfOpen on the next admission.
            open_duration: Duration::from_millis(0),
            test_requests: 3,
            ..Default::default()
        });
        let host = "reopen-probe.example.test";

        for _ in 0..5 {
            cb.record_failure(host);
        }
        // Spend all three trial tokens on transport failures → success_rate
        // 0.0 < 0.8 → back to Open.
        for _ in 0..3 {
            let mut permit = cb
                .begin_request(host)
                .expect("half-open must grant its trial tokens");
            permit.settle_transport_failure();
        }
        assert_eq!(cb.get_state(host), Some("open".to_string()));
        assert!(
            exported(OPENS, "transition", "reopened") > before_reopened,
            "{OPENS}{{transition=\"reopened\"}} did not move across a real \
             HalfOpen→Open re-open"
        );

        // Now the token-exhaustion block: hold the only trial token in flight
        // and ask for a second admission.
        let cb2 = HttpCircuitBreaker::new(CircuitBreakerConfig {
            open_duration: Duration::from_millis(0),
            test_requests: 1,
            ..Default::default()
        });
        let host2 = "exhaust-probe.example.test";
        for _ in 0..5 {
            cb2.record_failure(host2);
        }
        let inflight = cb2
            .begin_request(host2)
            .expect("first half-open trial is granted");
        assert!(
            cb2.begin_request(host2).is_none(),
            "second request must be refused — the single trial token is still in flight"
        );
        drop(inflight);
        assert!(
            exported(BLOCKS, "reason", "half_open_exhausted") > before_exhausted,
            "{BLOCKS}{{reason=\"half_open_exhausted\"}} did not move"
        );
    }

    // =======================================================================
    // The stranding: baseline, then the guard
    // =======================================================================

    /// **The pre-fix baseline, kept executable.**
    ///
    /// `allow_request` is the raw admission primitive as it stood on
    /// 2026-08-11 — it spends and never repays. Spend all three trial tokens
    /// through it and the circuit is stranded: `HalfOpen` has no time bound,
    /// so no amount of elapsed time produces another admission, and nothing in
    /// the code closes the loop. On the live worker this ran from 11:35 until
    /// a container recreate at 23:06.
    ///
    /// This test exists so "fixed" is falsifiable. Delete it and the only
    /// evidence that the bug was real becomes prose. It also pins the reason
    /// `allow_request` is `#[cfg(test)]`: the leak is a property of the
    /// primitive, not of its caller, so the primitive is not available to
    /// production code at all.
    #[test]
    fn strand_reproduction_the_raw_primitive_leaks_and_never_recovers() {
        let cb = HttpCircuitBreaker::new(CircuitBreakerConfig {
            open_duration: Duration::from_millis(10),
            test_requests: 3,
            ..Default::default()
        });
        let host = "strand-baseline.example.test";

        for _ in 0..5 {
            cb.record_failure(host);
        }
        assert_eq!(cb.get_state(host), Some("open".to_string()));

        // Past the cooldown → the next admission enters HalfOpen with three
        // trial tokens and immediately spends the first.
        std::thread::sleep(Duration::from_millis(20));
        for i in 0..3 {
            assert!(
                cb.allow_request(host),
                "trial {i} must be granted — the circuit has tokens"
            );
        }
        assert_eq!(cb.trial_tokens_remaining(host), Some(0));
        assert_eq!(cb.get_state(host), Some("half_open".to_string()));

        // No outcome was ever recorded for any of the three. Elapsed time is
        // irrelevant: the Open→HalfOpen re-entry that refills the tokens is
        // reachable only FROM Open, and this circuit is HalfOpen forever.
        for round in 0..5 {
            std::thread::sleep(Duration::from_millis(15));
            assert!(
                !cb.allow_request(host),
                "round {round}: still refused after {}ms — this is the strand",
                20 + 15 * (round + 1)
            );
        }
        assert_eq!(cb.trial_tokens_remaining(host), Some(0));
        assert_eq!(
            cb.trial_tally(host),
            Some((0, 0)),
            "no trial ever concluded, which is why the state machine cannot leave"
        );
    }

    /// The guard's whole job: an admission that is never settled costs
    /// nothing. Ten leaked permits in a row leave the circuit exactly where it
    /// started — which under `allow_request` (test above) would have stranded
    /// it on the third.
    #[test]
    fn dropping_a_permit_unsettled_repays_the_trial_token() {
        let cb = HttpCircuitBreaker::default();
        let host = "permit-drop.example.test";
        cb.force_half_open(host, 3);

        for i in 0..10 {
            let permit = cb
                .begin_request(host)
                .unwrap_or_else(|| panic!("admission {i} refused — a repaid token was not repaid"));
            drop(permit);
        }

        assert_eq!(cb.trial_tokens_remaining(host), Some(3));
        assert_eq!(cb.get_state(host), Some("half_open".to_string()));
        assert_eq!(
            cb.trial_tally(host),
            Some((0, 0)),
            "an abandoned trial is evidence of NOTHING: recording a synthetic \
             success could close the circuit against a dead host, and a \
             synthetic failure would hand any guest that can provoke an early \
             return a lever on shared state"
        );
    }

    /// `settle_no_evidence` — the reqwest-builder-error path — behaves like a
    /// drop for accounting purposes, and explicitly not like a failure.
    #[test]
    fn settling_with_no_evidence_repays_and_records_nothing() {
        let cb = HttpCircuitBreaker::default();
        let host = "no-evidence.example.test";
        cb.force_half_open(host, 2);

        let mut permit = cb.begin_request(host).expect("half-open admits");
        assert_eq!(cb.trial_tokens_remaining(host), Some(1));
        permit.settle_no_evidence();

        assert_eq!(cb.trial_tokens_remaining(host), Some(2));
        assert_eq!(cb.trial_tally(host), Some((0, 0)));
        assert_eq!(cb.get_state(host), Some("half_open".to_string()));
    }

    /// A guest that can provoke a client-side builder error must not be able
    /// to open a circuit that every other tenant on this worker shares.
    ///
    /// Pre-permit, `wit_http::fetch`'s `Err(e)` arm called `record_failure`
    /// unconditionally, and a malformed header NAME is a reqwest builder
    /// error — five such calls opened the host for everybody with no packet
    /// leaving the process.
    #[test]
    fn no_evidence_settlements_cannot_open_a_closed_circuit() {
        let cb = HttpCircuitBreaker::default();
        let host = "no-evidence-open.example.test";
        for _ in 0..20 {
            let mut permit = cb.begin_request(host).expect("closed circuit admits");
            permit.settle_no_evidence();
        }
        assert_eq!(cb.get_state(host), Some("closed".to_string()));
        assert_eq!(cb.consecutive_failures(host), Some(0));
    }

    /// Cancellation — the path that is not a statement and therefore cannot be
    /// patched per-`return`.
    ///
    /// The future is dropped while parked on an `.await` between the
    /// admission and the settle, exactly as an execution timeout, a worker
    /// shutdown, or a sibling failing a parallel fan-out drops it. On
    /// 2026-08-11 this is the shape that leaked `cal_personal`'s token.
    #[tokio::test]
    async fn a_cancelled_future_repays_its_trial_token() {
        let cb = HttpCircuitBreaker::default();
        let host = "cancelled.example.test";
        cb.force_half_open(host, 1);

        let inflight = async {
            let mut permit = cb.begin_request(host).expect("half-open admits");
            // Stand in for `resolve_vault_header().await` / `send().await`.
            futures_util::future::pending::<()>().await;
            permit.settle_response(200);
        };

        assert!(
            tokio::time::timeout(Duration::from_millis(25), inflight)
                .await
                .is_err(),
            "the probe future must still be parked when the timeout drops it"
        );

        assert_eq!(
            cb.trial_tokens_remaining(host),
            Some(1),
            "a dropped future must repay its trial token — this is the leak that \
             stranded www.googleapis.com for eleven and a half hours"
        );
        assert_eq!(cb.trial_tally(host), Some((0, 0)));
    }

    /// A permit that outlives its half-open period must not credit the NEXT
    /// one. Without the epoch stamp a slow in-flight request could hand a
    /// three-trial period a fourth trial.
    ///
    /// # This test was VACUOUS as shipped, and the fix is the interesting part
    ///
    /// The first version left the NEW period at exactly `test_requests` (3)
    /// and asserted the straggler's drop left it at 3. But `repay_trial_token`
    /// ends `.saturating_add(1).min(self.config.test_requests)`, so 3 is what
    /// it returns whether or not the epoch gate ran — the clamp alone
    /// satisfied the assertion. Confirmed by mutation on 2026-08-12: with the
    /// gate deleted outright, the shipped test still reported `ok`. A guard
    /// whose removal no test notices is not guarded.
    ///
    /// The fix is to put the current period BELOW the clamp ceiling before the
    /// straggler drops, so 2→2 (gate present) and 2→3 (gate absent) are
    /// distinguishable. Re-verified by mutation after the fix: deleting the
    /// gate fails this test.
    ///
    /// The new period's token is spent through `allow_request`, the retained
    /// leaking primitive, precisely because it takes a token WITHOUT creating
    /// a second permit whose own `Drop` would repay it and re-hide the bug.
    #[test]
    fn a_repayment_from_a_stale_half_open_period_is_discarded() {
        let cb = HttpCircuitBreaker::default();
        let host = "stale-epoch.example.test";
        cb.force_half_open(host, 1);

        let straggler = cb.begin_request(host).expect("half-open admits");
        assert_eq!(cb.trial_tokens_remaining(host), Some(0));

        // A new half-open period begins while the request is still in flight.
        // The sleep is what makes the two epochs distinguishable `Instant`s.
        std::thread::sleep(Duration::from_millis(2));
        cb.force_half_open(host, 3);

        // Spend one of the NEW period's three tokens, so the count sits at 2 —
        // strictly below the clamp ceiling. Without this the assertion below
        // holds for the wrong reason.
        assert!(cb.allow_request(host));
        assert_eq!(
            cb.trial_tokens_remaining(host),
            Some(2),
            "precondition: the current period must be BELOW its ceiling, or this \
             test cannot tell the gate from the clamp"
        );

        drop(straggler);
        assert_eq!(
            cb.trial_tokens_remaining(host),
            Some(2),
            "a token from a previous period must not inflate the current one; \
             seeing 3 here means the epoch gate in repay_trial_token is not running"
        );
    }

    /// The success side of a settle is epoch-gated too — the half of the
    /// symmetry that was MISSING until review on 2026-08-12.
    ///
    /// Both reviewers found it independently. `settle_response(200)` used to
    /// route through the ungated `record_success`, whose `HalfOpen` arm
    /// credits whatever period is current: a permit from a period that had
    /// already ended moved the CURRENT period's tally `(0,0) → (1,0)`, so a
    /// straggler could help close a period that did not earn it. The client
    /// timeout runs to 120 s against a 30 s cooldown, so the window is real.
    ///
    /// Fails without the gate in `record_trial_success` (the tally reads
    /// `(1,0)`), which is why it is a separate test from the tokens above.
    #[test]
    fn a_success_from_a_stale_half_open_period_is_discarded() {
        let cb = HttpCircuitBreaker::default();
        let host = "stale-epoch-success.example.test";
        cb.force_half_open(host, 1);

        let mut straggler = cb.begin_request(host).expect("half-open admits");

        std::thread::sleep(Duration::from_millis(2));
        cb.force_half_open(host, 3);
        assert_eq!(cb.trial_tally(host), Some((0, 0)));

        // The straggler's 200 belongs to a period that has already ended.
        straggler.settle_response(200);

        assert_eq!(
            cb.trial_tally(host),
            Some((0, 0)),
            "a success from a dead half-open period credited the current one — a \
             straggler must not help close a period it never ran in"
        );
        assert_eq!(cb.get_state(host).as_deref(), Some("half_open"));
    }

    /// A permit is ONE request and therefore ONE datapoint. The second settle
    /// must record nothing.
    ///
    /// `settled` was write-only until review on 2026-08-12 — all three settle
    /// methods set it and only `Drop` read it — while the filed follow-up for
    /// moving the settle past the response body asserted the opposite ("a
    /// second settle is a no-op rather than a double count") and then proposed
    /// the shape that double-settles. On a half-open trial that posts a
    /// success AND a failure from one probe, spends two of three slots, and at
    /// the default 3 trials / 0.8 threshold guarantees a re-open at 2/3.
    #[test]
    fn a_second_settle_records_nothing() {
        let cb = HttpCircuitBreaker::default();
        let host = "double-settle.example.test";
        cb.force_half_open(host, 3);

        let mut permit = cb.begin_request(host).expect("half-open admits");
        permit.settle_response(200);
        assert_eq!(cb.trial_tally(host), Some((1, 0)));

        // The shape the backlog entry proposed: settle again on the way out.
        permit.settle_response(500);
        permit.settle_transport_failure();
        permit.settle_no_evidence();

        assert_eq!(
            cb.trial_tally(host),
            Some((1, 0)),
            "one request produced more than one trial verdict"
        );
        assert_eq!(
            cb.consecutive_failures(host),
            Some(0),
            "a repeat settle reached the Closed-state failure counter"
        );
        assert_eq!(
            cb.trial_tokens_remaining(host),
            Some(2),
            "a repeat settle_no_evidence repaid a token that was already accounted for"
        );
    }

    /// `half_open_exhausted` does NOT require three-way concurrency.
    ///
    /// The change's own D4 note claimed it "now requires genuine 3-way
    /// concurrency", and the runbook told operators to look for requests
    /// racing. Both overstate it: trials that CONCLUDE do not repay their
    /// tokens, so two sequential failing trials leave one token, and a single
    /// caller arriving while the third trial is still in flight is refused.
    /// That is two-way — one in-flight trial and one arrival — and this test
    /// demonstrates it on ONE thread with no concurrency primitives at all.
    ///
    /// It also got MORE likely with this change, not less: before 2026-08-12 a
    /// 5xx trial counted as a success, and now it concludes the trial as a
    /// failure.
    #[test]
    fn half_open_exhausted_needs_no_three_way_concurrency() {
        let cb = HttpCircuitBreaker::default();
        let host = "sequential-exhaustion.example.test";
        cb.force_half_open(host, 3);

        // Two trials conclude, one strictly after the other. Neither re-opens:
        // the rate check runs only once all three verdicts are in.
        for i in 0..2 {
            let mut permit = cb
                .begin_request(host)
                .unwrap_or_else(|| panic!("trial {i} must be admitted"));
            permit.settle_response(503);
        }
        assert_eq!(cb.get_state(host).as_deref(), Some("half_open"));
        assert_eq!(cb.trial_tokens_remaining(host), Some(1));

        // The third trial is in flight. This is the ONLY outstanding request.
        let _third = cb.begin_request(host).expect("the last token");
        assert_eq!(cb.trial_tokens_remaining(host), Some(0));

        assert!(
            cb.begin_request(host).is_none(),
            "a caller arriving during a single in-flight trial must be refused \
             half_open_exhausted — no third concurrent request is needed"
        );
    }

    // =======================================================================
    // Connectivity vs health — the cross-tenant boundary
    // =======================================================================

    /// **The single most important test in this file.**
    ///
    /// The breaker is keyed by HOST and is one instance per worker PROCESS,
    /// which serves every user on the platform. If an HTTP status could open a
    /// circuit, one user's expired OAuth token (401) or exhausted per-user
    /// quota (429) would take `www.googleapis.com` away from every other
    /// user's calendar, Gmail and Drive workflows — a cross-tenant outage
    /// manufactured by a reliability feature.
    ///
    /// Four hundred settled responses across the whole status space, twenty
    /// per code against a threshold of five, and the circuit stays Closed.
    #[test]
    fn no_http_status_can_open_a_circuit() {
        for status in [400u16, 401, 403, 404, 422, 429, 500, 502, 503, 504] {
            let cb = HttpCircuitBreaker::default();
            let host = format!("status-cannot-open-{status}.example.test");
            for _ in 0..20 {
                let mut permit = cb
                    .begin_request(&host)
                    .expect("a closed circuit admits everything");
                permit.settle_response(status);
            }
            assert_eq!(
                cb.get_state(&host).as_deref(),
                Some("closed"),
                "HTTP {status} opened a process-global, host-keyed circuit — that is \
                 one tenant's credential, quota or payload deciding availability for \
                 every other tenant on this worker"
            );
            assert_eq!(
                cb.consecutive_failures(&host),
                Some(0),
                "HTTP {status} reached consecutive_failures, the only field the \
                 Closed→Open transition reads"
            );
        }
    }

    /// A recovery trial that gets a 401 CLOSES the circuit, and that is
    /// correct rather than a compromise: the trial asks "is this host alive
    /// and serving?", and a 401 answers yes. The credential problem behind it
    /// belongs to one user and must not be encoded in state every user shares.
    #[test]
    fn a_4xx_trial_closes_the_circuit_because_the_host_is_alive() {
        for status in [400u16, 401, 403, 404, 422] {
            let cb = HttpCircuitBreaker::default();
            let host = format!("trial-4xx-{status}.example.test");
            cb.force_half_open(&host, 3);
            for _ in 0..3 {
                let mut permit = cb.begin_request(&host).expect("half-open admits");
                permit.settle_response(status);
            }
            assert_eq!(
                cb.get_state(&host).as_deref(),
                Some("closed"),
                "HTTP {status} during a trial must count as recovery — the host answered"
            );
        }
    }

    /// **429 must NOT fail a trial.** The guard on the reversal made in review
    /// on 2026-08-12; if you are adding a status to
    /// `status_fails_recovery_trial`, this is the test that should stop you.
    ///
    /// A 429 is per-CALLER by construction — Google's `userRateLimitExceeded`
    /// is per-user — and this breaker is keyed by HOST and shared by every
    /// tenant on the worker process. With the shipped defaults
    /// (`test_requests = 3`, `success_rate_threshold = 0.8`) a period closes
    /// only on 3/3, so ONE rate-limited tenant taking ONE trial token dragged
    /// the period to 2/3 = 0.667 and re-opened the circuit for EVERYONE, one
    /// cooldown at a time, for as long as that tenant kept probing. That is a
    /// routine quota error manufacturing a cross-tenant outage.
    ///
    /// The pre-2026-08-12 behaviour was right here for the wrong reason (it
    /// counted every `Ok(resp)` as a success); the behaviour is restored on
    /// purpose, with the reason attached.
    #[test]
    fn a_429_trial_closes_the_circuit_because_the_quota_is_one_tenants() {
        let cb = HttpCircuitBreaker::default();
        let host = "trial-429.example.test";
        cb.force_half_open(host, 3);
        for _ in 0..3 {
            let mut permit = cb.begin_request(host).expect("half-open admits");
            permit.settle_response(429);
        }
        assert_eq!(
            cb.get_state(host).as_deref(),
            Some("closed"),
            "a 429 failed a recovery trial — one tenant's per-user quota just decided \
             availability for every other tenant sharing this worker's breaker"
        );
    }

    /// One 429 mixed into an otherwise clean trial period must not re-open
    /// either — the arithmetic, not just the unanimous case.
    ///
    /// This is the shape that actually occurs: one rate-limited tenant among
    /// several healthy ones. At 3 trials / 0.8 a single failed verdict is
    /// enough to force 2/3, so the unanimous test above would pass even if
    /// only two of three 429s counted.
    #[test]
    fn a_single_429_among_healthy_trials_still_closes_the_circuit() {
        let cb = HttpCircuitBreaker::default();
        let host = "trial-429-mixed.example.test";
        cb.force_half_open(host, 3);

        for status in [200u16, 429, 200] {
            let mut permit = cb.begin_request(host).expect("half-open admits");
            permit.settle_response(status);
        }
        assert_eq!(
            cb.get_state(host).as_deref(),
            Some("closed"),
            "one tenant's 429 re-opened a circuit shared by every other tenant"
        );
        assert_eq!(cb.trial_tally(host), Some((3, 0)));
    }

    /// The residual tail, asserted rather than asserted-about: with 429
    /// removed, ONE 5xx anywhere in a three-trial period still re-opens.
    ///
    /// Stated in the "connectivity-vs-health" note and accepted there. It is
    /// pinned here so the acceptance is a measured property and not a claim —
    /// and so that any future tuning of `test_requests` /
    /// `success_rate_threshold` has to come past a test that says what the
    /// current numbers mean.
    #[test]
    fn one_5xx_in_a_trial_period_is_enough_to_reopen() {
        let cb = HttpCircuitBreaker::default();
        let host = "trial-one-5xx.example.test";
        cb.force_half_open(host, 3);

        for status in [200u16, 500, 200] {
            let mut permit = cb.begin_request(host).expect("half-open admits");
            permit.settle_response(status);
        }
        assert_eq!(
            cb.get_state(host).as_deref(),
            Some("open"),
            "2/3 = 0.667 is below the 0.8 threshold, so the period re-opens — this is \
             the accepted residual tail, not a surprise"
        );
        assert_eq!(cb.trial_tally(host), Some((2, 1)));
    }

    /// The half of bug 2 that was a genuine correctness defect: pre-change,
    /// every trial that got an `Ok(resp)` counted as a success regardless of
    /// status, so a host answering nothing but 503 scored a 100% success rate
    /// and had its circuit CLOSED — full traffic resumed onto an upstream that
    /// was serving nothing.
    ///
    /// Also the D4 attribution check: this is the transition that should make
    /// `talos_circuit_breaker_opens_total{transition="reopened"}` move after
    /// this change, on hosts where it previously showed a close.
    #[test]
    fn a_5xx_trial_reopens_the_circuit_instead_of_closing_it() {
        const OPENS: &str = "talos_circuit_breaker_opens_total";
        let before_reopened = exported(OPENS, "transition", "reopened");

        for status in [500u16, 502, 503, 504] {
            let cb = HttpCircuitBreaker::default();
            let host = format!("trial-unhealthy-{status}.example.test");
            cb.force_half_open(&host, 3);
            for _ in 0..3 {
                let mut permit = cb.begin_request(&host).expect("half-open admits");
                permit.settle_response(status);
            }
            assert_eq!(
                cb.get_state(&host).as_deref(),
                Some("open"),
                "a trial answered with HTTP {status} is not evidence of recovery; \
                 pre-2026-08-12 this closed the circuit"
            );
            assert_eq!(cb.trial_tally(&host), Some((0, 3)));
        }

        assert!(
            exported(OPENS, "transition", "reopened") > before_reopened,
            "{OPENS}{{transition=\"reopened\"}} did not move — the status-driven \
             trial verdict is not wired to the counter that is supposed to attribute it"
        );
    }

    /// The structural guarantee behind the cross-tenant argument: a trial
    /// verdict arriving after the circuit has left `HalfOpen` is discarded, so
    /// a status can never be replayed into the Closed-state failure counter.
    ///
    /// Without this, a permit taken during a trial and settled with a 500
    /// after a concurrent trial had already closed the circuit would land in
    /// `record_failure`'s Closed arm — and five of those would open a
    /// host-keyed, process-global circuit off nothing but HTTP status.
    #[test]
    fn a_trial_status_failure_cannot_reach_the_closed_state_failure_counter() {
        let cb = HttpCircuitBreaker::default();
        let host = "trial-late-settle.example.test";
        // Four tokens so one permit can stay in flight while three others
        // conclude the trial period.
        cb.force_half_open(host, 4);

        let mut inflight = cb.begin_request(host).expect("half-open admits");
        for _ in 0..3 {
            let mut permit = cb.begin_request(host).expect("half-open admits");
            permit.settle_response(200);
        }
        assert_eq!(
            cb.get_state(host),
            Some("closed".to_string()),
            "three clean trials must close the circuit"
        );

        // The straggler now reports a 500 against a circuit that has already
        // closed.
        inflight.settle_response(500);

        assert_eq!(cb.get_state(host), Some("closed".to_string()));
        assert_eq!(
            cb.consecutive_failures(host),
            Some(0),
            "a half-open trial verdict leaked into the Closed-state counter"
        );
    }

    /// A transport failure still opens circuits exactly as before. The point
    /// of the change is that STATUS cannot; connectivity must be untouched.
    #[test]
    fn transport_failures_still_open_circuits_unchanged() {
        let cb = HttpCircuitBreaker::default();
        let host = "transport-still-opens.example.test";
        for _ in 0..5 {
            let mut permit = cb.begin_request(host).expect("closed circuit admits");
            permit.settle_transport_failure();
        }
        assert_eq!(cb.get_state(host), Some("open".to_string()));
    }

    /// No breaker method may hold a DashMap shard across a call into another
    /// breaker method, because same-shard re-entry self-deadlocks. The metric
    /// increments are likewise taken after every entry guard has dropped.
    ///
    /// Eight threads hammer a small host pool — small on purpose, so the
    /// entries collide on the same shards — mixing every settle path plus the
    /// unsettled drop, under a watchdog. A held guard hangs; the watchdog
    /// turns the hang into a failure.
    ///
    /// NEGATIVE CONTROL, RUN 2026-08-12 so this assertion is not vacuous.
    /// `RequestPermit::settle_transport_failure` was temporarily changed to
    /// take the host's entry guard and hold it across its `record_failure`
    /// call — the exact "simplification" a future reader might make — and the
    /// suite reported:
    ///
    /// ```text
    /// test circuit_breaker::tests::concurrent_admissions_and_settlements_never_deadlock ... FAILED
    /// worker 0 did not finish within 30s (timed out waiting on channel)
    ///   — a breaker method is holding a DashMap shard across a call that
    ///     re-enters the map
    /// ```
    ///
    /// The mutation was reverted immediately. The result is recorded here
    /// rather than shipped, because a test that must hang cannot live in a
    /// suite.
    ///
    /// LIMITATION, stated rather than implied: what this catches is re-entry
    /// into the BREAKER. It does NOT catch a metric increment moved inside an
    /// entry guard, because `prometheus::IntCounter::inc` never re-enters the
    /// map and so cannot deadlock — that half of the property (every
    /// `record_*` computes its transition inside a block and increments after
    /// the block closes) is held by the code's shape and by review, not by
    /// this test.
    #[test]
    fn concurrent_admissions_and_settlements_never_deadlock() {
        let cb = Arc::new(HttpCircuitBreaker::new(CircuitBreakerConfig {
            open_duration: Duration::from_millis(0),
            test_requests: 3,
            ..Default::default()
        }));
        let hosts = ["shard-a.example.test", "shard-b.example.test"];
        let (tx, rx) = std::sync::mpsc::channel::<()>();

        let mut handles = Vec::new();
        for t in 0..8u32 {
            let cb = cb.clone();
            let tx = tx.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..250u32 {
                    let host = hosts[(t as usize + i as usize) % hosts.len()];
                    if let Some(mut permit) = cb.begin_request(host) {
                        match (t + i) % 4 {
                            0 => permit.settle_response(200),
                            1 => permit.settle_response(503),
                            2 => permit.settle_transport_failure(),
                            // The unsettled drop.
                            _ => {}
                        }
                    }
                }
                let _ = tx.send(());
            }));
        }
        drop(tx);

        for worker in 0..8 {
            rx.recv_timeout(Duration::from_secs(30))
                .unwrap_or_else(|e| {
                    panic!(
                        "worker {worker} did not finish within 30s ({e}) — a breaker method \
                     is holding a DashMap shard across a call that re-enters the map"
                    )
                });
        }
        for h in handles {
            h.join().expect("no worker may panic");
        }

        for host in hosts {
            if let Some(remaining) = cb.trial_tokens_remaining(host) {
                assert!(
                    remaining <= 3,
                    "{host}: {remaining} trial tokens outstanding against a \
                     three-token budget — repayment is over-crediting"
                );
            }
        }
    }

    /// All five series must EXIST after seeding, so `increase(...) > 0` is
    /// well-defined on a worker that has never tripped the breaker rather than
    /// evaluating over an absent series and matching nothing.
    ///
    /// LIMITATION, stated rather than implied: this asserts PRESENCE, not
    /// "present AND zero". The counters are process-global and this binary's
    /// other tests trip breakers in parallel, so no test in this binary can
    /// observe a genuinely cold value. The at-zero half follows structurally —
    /// `IntCounterVec::with_label_values` materialises each child at 0 at
    /// registration time, before any breaker exists — and is checkable on a
    /// real worker by scraping `/metrics` before its first trip.
    #[test]
    fn seeding_exports_every_label_combination() {
        seed_circuit_breaker_series();
        let text = crate::metrics::get_prometheus_metrics();
        for expected in [
            r#"talos_circuit_breaker_opens_total{transition="opened""#,
            r#"talos_circuit_breaker_opens_total{transition="reopened""#,
            r#"talos_circuit_breaker_blocks_total{reason="cooldown""#,
            r#"talos_circuit_breaker_blocks_total{reason="half_open_exhausted""#,
            r#"talos_circuit_breaker_blocks_total{reason="retry_gate""#,
        ] {
            assert!(
                text.contains(expected),
                "seeded series {expected} is absent from the exposition; an \
                 alert of the shape increase(...) > 0 would be silent on a \
                 worker that has never tripped the breaker.\n{text}"
            );
        }
    }
}
