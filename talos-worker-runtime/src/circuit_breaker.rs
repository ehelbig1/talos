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
// `wit_http::fetch_all` does not interact with the breaker at all — it neither
// consults it nor records outcomes — so BOTH series are structurally blind to
// batch HTTP. Latent today (no shipped module template calls it) and argued at
// length at that function's `send()` in `host/http.rs`, including why extending
// it is a design question rather than a line. Any runbook sentence of the form
// "if these are flat, the breaker is not involved" must be read with that
// exception attached; the alert description states it.
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
//    "recorded outside the entry lock" note on `allow_request`.
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
    /// downstream: `allow_request` returns `false` for both, and `host/http.rs`
    /// has a single `emit_network_failure` behind that one `false`, so both
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
    pub fn allow_request(&self, host: &str) -> bool {
        let blocked = {
            let now = Instant::now();
            let mut entry = self
                .records
                .entry(host.to_string())
                .or_insert_with(CircuitRecord::new);
            let record = entry.value_mut();

            let mut blocked: Option<BlockReason> = None;

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
                    blocked = Some(BlockReason::Cooldown);
                }
            }

            // In half-open state, only allow test requests
            if blocked.is_none() && record.state == CircuitState::HalfOpen {
                if record.test_requests_remaining == 0 {
                    // No more test requests allowed, reject
                    blocked = Some(BlockReason::HalfOpenExhausted);
                } else {
                    record.test_requests_remaining -= 1;
                }
            }

            blocked
        };

        match blocked {
            Some(reason) => {
                BREAKER_METRICS.record_block(reason);
                false
            }
            None => true,
        }
    }

    /// Record a successful request to the given host.
    ///
    /// Metric recorded after the entry guard drops (see [`Self::allow_request`]).
    /// The overwhelmingly common case — a success on a Closed circuit — takes
    /// no metric path at all.
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
    /// Metric recorded after the entry guard drops (see [`Self::allow_request`]).
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
    /// Distinct from [`Self::allow_request`], which MUTATES (drives the
    /// Open→HalfOpen transition and the half-open test-token accounting).
    /// `is_open` never mutates — it is the retry-decision gate: when a
    /// host's circuit is OPEN and cooling down, in-worker retries against
    /// it are pointless (the outage is sustained), so the retry loop
    /// short-circuits and fails fast instead of burning its budget on a
    /// host we already know is down.
    ///
    /// Returns `false` once the cooldown has elapsed (the circuit is
    /// ready for a half-open trial) so the next real request still gets
    /// its single probe via `allow_request`, and `false` for a host with
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
    /// the PRODUCTION methods (`record_failure`, `allow_request`,
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
            !cb.allow_request(host),
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
    #[test]
    fn half_open_reopen_and_token_exhaustion_move_their_own_labels() {
        const OPENS: &str = "talos_circuit_breaker_opens_total";
        const BLOCKS: &str = "talos_circuit_breaker_blocks_total";

        let before_reopened = exported(OPENS, "transition", "reopened");
        let before_exhausted = exported(BLOCKS, "reason", "half_open_exhausted");

        let cb = HttpCircuitBreaker::new(CircuitBreakerConfig {
            // Straight to HalfOpen on the next allow_request.
            open_duration: Duration::from_millis(0),
            test_requests: 3,
            ..Default::default()
        });
        let host = "reopen-probe.example.test";

        for _ in 0..5 {
            cb.record_failure(host);
        }
        // Spend all three trial tokens on failures → success_rate 0.0 < 0.8 →
        // back to Open.
        for _ in 0..3 {
            assert!(
                cb.allow_request(host),
                "half-open must grant its trial tokens"
            );
            cb.record_failure(host);
        }
        assert_eq!(cb.get_state(host), Some("open".to_string()));
        assert!(
            exported(OPENS, "transition", "reopened") > before_reopened,
            "{OPENS}{{transition=\"reopened\"}} did not move across a real \
             HalfOpen→Open re-open"
        );

        // Now the token-exhaustion block: force HalfOpen again and drain the
        // tokens without recording outcomes, so the next request is refused
        // with no state change.
        let cb2 = HttpCircuitBreaker::new(CircuitBreakerConfig {
            open_duration: Duration::from_millis(0),
            test_requests: 1,
            ..Default::default()
        });
        let host2 = "exhaust-probe.example.test";
        for _ in 0..5 {
            cb2.record_failure(host2);
        }
        assert!(cb2.allow_request(host2), "first half-open trial is granted");
        assert!(
            !cb2.allow_request(host2),
            "second request must be refused — the single trial token is spent"
        );
        assert!(
            exported(BLOCKS, "reason", "half_open_exhausted") > before_exhausted,
            "{BLOCKS}{{reason=\"half_open_exhausted\"}} did not move"
        );
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
