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
/// the alert rules in `observability/alerts.yml` selected on the SINGLE-
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

/// Normalize LLM provider labels to fixed set
fn normalize_llm_provider(provider: &str) -> &'static str {
    match provider {
        "anthropic" => "anthropic",
        "openai" => "openai",
        "gemini" => "gemini",
        _ => "other",
    }
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

    /// LLM API requests by provider (anthropic, openai, gemini)
    pub llm_requests: Counter<u64>,
    /// LLM token usage by direction (input, output)
    pub llm_token_usage: Counter<u64>,
    /// LLM request duration (milliseconds)
    pub llm_duration: Histogram<f64>,

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

            execution_duration: meter
                .f64_histogram("wasm.execution.duration_ms")
                .with_description("Execution duration in milliseconds")
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

            llm_requests: meter
                .u64_counter("wasm.llm.requests")
                .with_description("LLM API requests by provider")
                .build(),
            llm_token_usage: meter
                .u64_counter("wasm.llm.token_usage")
                .with_description("LLM token usage by direction")
                .build(),
            llm_duration: meter
                .f64_histogram("wasm.llm.duration_ms")
                .with_description("LLM request duration in milliseconds")
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
    /// * `errors` / `retries` / `llm.*` / `approval.*` / `quota.*` /
    ///   `host_function.*` — NOT seeded. Their label populations are driven
    ///   by which failure or which host call actually happened, so a seeded
    ///   combination would assert a class of event is being watched for when
    ///   nothing distinguishes "zero timeouts" from "the timeout path was
    ///   deleted". Their alerts are `> threshold` shapes, which behave
    ///   correctly over an absent series (no data, no alert).
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

    /// Record an LLM API request.
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
