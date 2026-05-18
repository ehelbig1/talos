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
#[allow(dead_code)]
use opentelemetry::{global, metrics::*, KeyValue};
use std::sync::atomic::{AtomicU64, Ordering};

// ========================================================================
// 🔥 SECURITY: Label Normalization
// Prevent unbounded cardinality which can cause memory exhaustion
// ========================================================================

/// Normalize status labels to fixed set to prevent unbounded cardinality
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
    /// Memory usage in bytes
    memory_used: Gauge<u64>,
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
    // 🔥 PERFORMANCE: Atomic counters for cache hit rate calculation
    // ========================================================================
    /// Atomic counter for total cache hits (for hit rate calculation)
    cache_hits_count: AtomicU64,
    /// Atomic counter for total cache misses (for hit rate calculation)
    cache_misses_count: AtomicU64,
}

#[allow(dead_code)]
impl RuntimeMetrics {
    /// Initialize OpenTelemetry metrics
    pub fn new() -> Self {
        let meter = global::meter("talos-wasm-runtime");

        Self {
            executions_total: meter
                .u64_counter("wasm.executions.total")
                .with_description("Total WASM executions")
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

            memory_used: meter
                .u64_gauge("wasm.memory.used_bytes")
                .with_description("Memory used by WASM instances (bytes)")
                .build(),

            active_instances: meter
                .i64_up_down_counter("wasm.instances.active")
                .with_description("Currently active WASM instances")
                .build(),
            total_executions: meter
                .u64_counter("wasm.executions.total")
                .with_description("Total WASM executions (cumulative)")
                .build(),
            cache_hit_ratio: meter
                .f64_gauge("wasm.cache.hit_ratio")
                .with_description("Cache hit ratio (0.0‑1.0)")
                .build(),

            compilation_duration: meter
                .f64_histogram("wasm.compilation.duration_ms")
                .with_description("Module compilation duration in milliseconds")
                .build(),

            retry_attempts: meter
                .u64_counter("wasm.retries.total")
                .with_description("Total retry attempts")
                .build(),

            errors_total: meter
                .u64_counter("wasm.errors.total")
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

            // Initialize atomic counters
            cache_hits_count: AtomicU64::new(0),
            cache_misses_count: AtomicU64::new(0),
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

    /// Update memory usage gauge
    pub fn update_memory_usage(&self, bytes: u64) {
        self.memory_used.record(bytes, &[]);
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
///     worker::metrics::get_prometheus_metrics()
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
