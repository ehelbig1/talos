//! Prometheus metrics instrumentation for Talos controller.
//!
//! This module provides metrics for:
//! - Webhook request counts and latencies
//! - Authentication success/failure rates
//! - Module execution counts and duration
//! - Rate limiter hits
//! - Cache hit/miss rates
//! - DLQ metrics

use prometheus::{exponential_buckets, Counter, CounterVec, HistogramVec, IntGauge, Registry};
use std::sync::{Arc, OnceLock};

/// Process-global metrics registry.
///
/// Initialised once in `main.rs` after [`TalosMetrics::new`] succeeds.
/// Subsystems use [`global()`] to emit metrics without threading an
/// `Arc<TalosMetrics>` through every constructor. Safe concurrent reads;
/// writes are one-shot at startup.
static METRICS: OnceLock<Arc<TalosMetrics>> = OnceLock::new();

/// Install the process-global metrics registry. Idempotent —
/// subsequent calls return the already-installed value.
pub fn set_global(metrics: Arc<TalosMetrics>) {
    let _ = METRICS.set(metrics);
}

/// Access the process-global metrics registry. Returns `None` when
/// called before [`set_global`] (e.g. from a unit test). Callers MUST
/// use `.map(|m| m.counter.inc())` idiom — never unwrap.
pub fn global() -> Option<&'static Arc<TalosMetrics>> {
    METRICS.get()
}

/// Global metrics registry and collectors
pub struct TalosMetrics {
    pub registry: Registry,

    // Webhook metrics
    pub webhook_requests_total: CounterVec,
    pub webhook_request_duration_seconds: HistogramVec,
    pub webhook_dlq_drops_total: Counter,

    // Authentication metrics
    pub auth_attempts_total: CounterVec,
    pub auth_failures_total: CounterVec,
    pub auth_2fa_attempts_total: CounterVec,
    pub api_key_validations_total: CounterVec,

    // Execution metrics
    pub module_executions_total: CounterVec,
    pub module_execution_duration_seconds: HistogramVec,
    pub workflow_executions_total: CounterVec,
    pub workflow_execution_duration_seconds: HistogramVec,

    // Crash-recovery metrics (durable execution, RFC 0003). Labeled by
    // `outcome`: resumed | failed | reclaimed. Lets operators alert on a
    // restart-resume sweep that silently does nothing or whose resumes fail.
    pub crash_recovery_total: CounterVec,

    // Rate limiting metrics
    pub rate_limit_hits_total: CounterVec,

    // Cache metrics
    pub cache_hits_total: CounterVec,
    pub cache_misses_total: CounterVec,

    // Circuit breaker metrics
    pub circuit_breaker_opens_total: Counter,
    pub circuit_breaker_blocks_total: Counter,

    // DLQ metrics
    pub dlq_entries_total: Counter,
    pub dlq_drops_total: Counter,
    pub dlq_db_errors_total: Counter,

    // Crypto-invariant metrics. These are the highest-blast-radius
    // signals the platform exposes — a Vault outage or KEK / DEK
    // drift causes silent encrypted-at-rest data loss.
    // See deploy/observability/alerts.yaml for the SLOs built on top.
    pub kek_decrypt_failures_total: CounterVec,
    pub memory_write_failures_total: CounterVec,
    /// `ops_alerts` ingest failures from the `__ops_alert__` hook.
    /// Labels: reason=validation|db|tenancy. Sustained bump means alert
    /// envelopes emitted by parser modules are being lost.
    pub ops_alert_ingest_failures_total: CounterVec,
    pub module_payload_encryption_failures_total: CounterVec,
    /// Per-row secret-decrypt failures from `SecretsManager::get_module_secrets`.
    /// Labels: reason=missing_dek|cipher_init|aead|invalid_utf8|too_short.
    /// Sustained bump means a module is missing some of its expected
    /// secrets at runtime — `vault://` substitutions will fail with
    /// `Notfound` and HTTP calls will be unauthenticated.
    pub secret_decrypt_failures_total: CounterVec,
    pub actor_memory_orphaned_rows: IntGauge,
    pub module_execution_orphaned_rows: IntGauge,
    pub workflow_execution_orphaned_rows: IntGauge,
    pub dek_cache_size: IntGauge,
    /// Total connections currently held by the controller's sqlx
    /// Postgres pool (idle + in-use). Sampled periodically by a
    /// controller sweep task. Bounded above by `DB_MAX_CONNECTIONS`.
    pub db_pool_connections: IntGauge,
    /// Connections in the pool that are idle (available to hand out).
    pub db_pool_idle_connections: IntGauge,
    /// Connections currently checked out and in use
    /// (`connections - idle`). When this sits at `DB_MAX_CONNECTIONS`,
    /// new acquisitions block on the 10 s acquire timeout — the pool is
    /// saturated and request latency climbs across the whole process.
    pub db_pool_in_use_connections: IntGauge,
    /// The configured max pool size (`DB_MAX_CONNECTIONS`), exported as
    /// a gauge so alerts can compute a saturation RATIO
    /// (`in_use / max`) without hardcoding the limit in PromQL.
    pub db_pool_max_connections: IntGauge,
}

impl TalosMetrics {
    /// Create and register all metrics
    pub fn new() -> anyhow::Result<Arc<Self>> {
        let registry = Registry::new();

        // Webhook metrics
        let webhook_requests_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_webhook_requests_total",
                "Total number of webhook requests received",
            ),
            &["trigger_id", "status"],
        )?;
        registry.register(Box::new(webhook_requests_total.clone()))?;

        let webhook_request_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "talos_webhook_request_duration_seconds",
                "Webhook request duration in seconds",
            )
            .buckets(exponential_buckets(0.001, 2.0, 15).expect("valid exponential buckets")),
            &["trigger_id"],
        )?;
        registry.register(Box::new(webhook_request_duration_seconds.clone()))?;

        let webhook_dlq_drops_total = Counter::new(
            "talos_webhook_dlq_drops_total",
            "Total number of webhook requests dropped to DLQ",
        )?;
        registry.register(Box::new(webhook_dlq_drops_total.clone()))?;

        // Authentication metrics
        let auth_attempts_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_auth_attempts_total",
                "Total number of authentication attempts",
            ),
            &["method"], // password, oauth, api_key
        )?;
        registry.register(Box::new(auth_attempts_total.clone()))?;

        let auth_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_auth_failures_total",
                "Total number of authentication failures",
            ),
            &["method", "reason"], // invalid_password, rate_limited, locked, etc.
        )?;
        registry.register(Box::new(auth_failures_total.clone()))?;

        let auth_2fa_attempts_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_auth_2fa_attempts_total",
                "Total number of 2FA verification attempts",
            ),
            &["status"], // success, failure
        )?;
        registry.register(Box::new(auth_2fa_attempts_total.clone()))?;

        let api_key_validations_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_api_key_validations_total",
                "Total number of API key validations",
            ),
            &["status"], // valid, invalid, expired, rate_limited
        )?;
        registry.register(Box::new(api_key_validations_total.clone()))?;

        // Execution metrics
        let module_executions_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_module_executions_total",
                "Total number of module executions",
            ),
            &["status", "trigger_type"], // success, failure, timeout
        )?;
        registry.register(Box::new(module_executions_total.clone()))?;

        let module_execution_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "talos_module_execution_duration_seconds",
                "Module execution duration in seconds",
            )
            .buckets(exponential_buckets(0.01, 2.0, 15).expect("valid exponential buckets")),
            &["status"],
        )?;
        registry.register(Box::new(module_execution_duration_seconds.clone()))?;

        let workflow_executions_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_workflow_executions_total",
                "Total number of workflow executions",
            ),
            &["status"], // success, failure, timeout, cancelled
        )?;
        registry.register(Box::new(workflow_executions_total.clone()))?;

        let workflow_execution_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "talos_workflow_execution_duration_seconds",
                "Workflow execution duration in seconds",
            )
            .buckets(exponential_buckets(0.1, 2.0, 15).expect("valid exponential buckets")),
            &["status"],
        )?;
        registry.register(Box::new(workflow_execution_duration_seconds.clone()))?;

        let crash_recovery_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_crash_recovery_total",
                "Total crash-recovery resume outcomes since process start",
            ),
            &["outcome"], // resumed, failed, reclaimed
        )?;
        registry.register(Box::new(crash_recovery_total.clone()))?;
        // Pre-seed the outcome series to 0. Unlike the high-frequency execution
        // counters above, crash-recovery only fires on a restart-with-orphans,
        // so without seeding these series would be absent in steady state and
        // `rate()` / absence alerts + dashboard panels would have nothing to
        // reference. A counter seeded at 0 is correct and always present.
        for outcome in ["resumed", "failed", "reclaimed"] {
            crash_recovery_total
                .with_label_values(&[outcome])
                .inc_by(0.0);
        }

        // Rate limiting metrics
        let rate_limit_hits_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_rate_limit_hits_total",
                "Total number of rate limit hits",
            ),
            &["type"], // ip, api_key, webhook
        )?;
        registry.register(Box::new(rate_limit_hits_total.clone()))?;

        // Cache metrics
        let cache_hits_total = CounterVec::new(
            prometheus::Opts::new("talos_cache_hits_total", "Total number of cache hits"),
            &["cache_type"], // wasm, secret, dek
        )?;
        registry.register(Box::new(cache_hits_total.clone()))?;

        let cache_misses_total = CounterVec::new(
            prometheus::Opts::new("talos_cache_misses_total", "Total number of cache misses"),
            &["cache_type"],
        )?;
        registry.register(Box::new(cache_misses_total.clone()))?;

        // Circuit breaker metrics
        let circuit_breaker_opens_total = Counter::new(
            "talos_circuit_breaker_opens_total",
            "Total number of circuit breaker opens",
        )?;
        registry.register(Box::new(circuit_breaker_opens_total.clone()))?;

        let circuit_breaker_blocks_total = Counter::new(
            "talos_circuit_breaker_blocks_total",
            "Total number of requests blocked by circuit breaker",
        )?;
        registry.register(Box::new(circuit_breaker_blocks_total.clone()))?;

        // DLQ metrics
        let dlq_entries_total = Counter::new(
            "talos_dlq_entries_total",
            "Total number of DLQ entries created",
        )?;
        registry.register(Box::new(dlq_entries_total.clone()))?;

        let dlq_drops_total = Counter::new(
            "talos_dlq_drops_total",
            "Total number of DLQ entries dropped (channel full)",
        )?;
        registry.register(Box::new(dlq_drops_total.clone()))?;

        let dlq_db_errors_total = Counter::new(
            "talos_dlq_db_errors_total",
            "Total number of DLQ database write errors",
        )?;
        registry.register(Box::new(dlq_db_errors_total.clone()))?;

        // ---- Crypto-invariant metrics ----
        let kek_decrypt_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_kek_decrypt_failures_total",
                "DEK unwrap failures. Labels: provider=active|legacy|both. \
                 Any bump here means encrypted-at-rest data is currently \
                 unreadable — page operator immediately.",
            ),
            &["provider"],
        )?;
        registry.register(Box::new(kek_decrypt_failures_total.clone()))?;

        let memory_write_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_memory_write_failures_total",
                "actor_memory persistence failures from the __memory_write__ \
                 hook. Labels: reason=crypto|db|validation. Sustained bump \
                 means node outputs are being lost to disk.",
            ),
            &["reason"],
        )?;
        registry.register(Box::new(memory_write_failures_total.clone()))?;

        let ops_alert_ingest_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_ops_alert_ingest_failures_total",
                "ops_alerts persistence failures from the __ops_alert__ \
                 hook. Labels: reason=validation|db|tenancy. Sustained bump \
                 means parser-module alert envelopes are being lost.",
            ),
            &["reason"],
        )?;
        registry.register(Box::new(ops_alert_ingest_failures_total.clone()))?;

        let module_payload_encryption_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_module_payload_encryption_failures_total",
                "module_executions payload encrypt/decrypt failures. \
                 Labels: op=encrypt|decrypt, stage=input|output|trigger_metadata.",
            ),
            &["op", "stage"],
        )?;
        registry.register(Box::new(module_payload_encryption_failures_total.clone()))?;

        let secret_decrypt_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_secret_decrypt_failures_total",
                "Per-row secret decrypt failures inside get_module_secrets. \
                 Labels: reason=missing_dek|cipher_init|aead|invalid_utf8|too_short.",
            ),
            &["reason"],
        )?;
        registry.register(Box::new(secret_decrypt_failures_total.clone()))?;

        let actor_memory_orphaned_rows = IntGauge::new(
            "talos_actor_memory_orphaned_rows",
            "Rows in actor_memory whose value_key_id points at a DEK that \
             no longer exists in encryption_keys. Should be 0. Non-zero = \
             data loss already occurred, investigate immediately.",
        )?;
        registry.register(Box::new(actor_memory_orphaned_rows.clone()))?;

        let module_execution_orphaned_rows = IntGauge::new(
            "talos_module_execution_orphaned_rows",
            "Rows in module_executions whose payload_enc_key_id points at a \
             missing DEK. Should be 0.",
        )?;
        registry.register(Box::new(module_execution_orphaned_rows.clone()))?;

        let workflow_execution_orphaned_rows = IntGauge::new(
            "talos_workflow_execution_orphaned_rows",
            "Rows in workflow_executions whose output_enc_key_id points at a \
             missing DEK. Should be 0.",
        )?;
        registry.register(Box::new(workflow_execution_orphaned_rows.clone()))?;

        let dek_cache_size = IntGauge::new(
            "talos_dek_cache_size",
            "Current number of DEKs held in the in-memory decryption cache. \
             Bounded by TTL eviction + write-path invalidation.",
        )?;
        registry.register(Box::new(dek_cache_size.clone()))?;

        let db_pool_connections = IntGauge::new(
            "talos_db_pool_connections",
            "Total connections held by the controller's Postgres pool (idle + in-use).",
        )?;
        registry.register(Box::new(db_pool_connections.clone()))?;

        let db_pool_idle_connections = IntGauge::new(
            "talos_db_pool_idle_connections",
            "Idle connections in the controller's Postgres pool (available to hand out).",
        )?;
        registry.register(Box::new(db_pool_idle_connections.clone()))?;

        let db_pool_in_use_connections = IntGauge::new(
            "talos_db_pool_in_use_connections",
            "Connections currently checked out of the controller's Postgres pool. \
             At DB_MAX_CONNECTIONS the pool is saturated and acquisitions block.",
        )?;
        registry.register(Box::new(db_pool_in_use_connections.clone()))?;

        let db_pool_max_connections = IntGauge::new(
            "talos_db_pool_max_connections",
            "Configured maximum size of the controller's Postgres pool (DB_MAX_CONNECTIONS).",
        )?;
        registry.register(Box::new(db_pool_max_connections.clone()))?;

        Ok(Arc::new(Self {
            registry,
            webhook_requests_total,
            webhook_request_duration_seconds,
            webhook_dlq_drops_total,
            auth_attempts_total,
            auth_failures_total,
            auth_2fa_attempts_total,
            api_key_validations_total,
            module_executions_total,
            module_execution_duration_seconds,
            workflow_executions_total,
            workflow_execution_duration_seconds,
            crash_recovery_total,
            rate_limit_hits_total,
            cache_hits_total,
            cache_misses_total,
            circuit_breaker_opens_total,
            circuit_breaker_blocks_total,
            dlq_entries_total,
            dlq_drops_total,
            dlq_db_errors_total,
            kek_decrypt_failures_total,
            memory_write_failures_total,
            ops_alert_ingest_failures_total,
            module_payload_encryption_failures_total,
            secret_decrypt_failures_total,
            actor_memory_orphaned_rows,
            module_execution_orphaned_rows,
            workflow_execution_orphaned_rows,
            dek_cache_size,
            db_pool_connections,
            db_pool_idle_connections,
            db_pool_in_use_connections,
            db_pool_max_connections,
        }))
    }

    /// Export metrics in Prometheus text format
    pub fn gather(&self) -> Vec<prometheus::proto::MetricFamily> {
        self.registry.gather()
    }

    /// Render the gathered registry into the Prometheus text exposition
    /// format. Returned string is UTF-8 and safe to drop into a
    /// `text/plain; version=0.0.4` HTTP response body.
    pub fn render_prometheus(&self) -> Result<String, prometheus::Error> {
        use prometheus::Encoder as _;
        let encoder = prometheus::TextEncoder::new();
        let mut buf = Vec::with_capacity(8192);
        encoder.encode(&self.gather(), &mut buf)?;
        String::from_utf8(buf).map_err(|e| prometheus::Error::Msg(format!("utf-8: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = TalosMetrics::new();
        assert!(metrics.is_ok());
    }

    #[test]
    fn test_metrics_increment() {
        let metrics = TalosMetrics::new().unwrap();

        // Increment a counter
        metrics.dlq_entries_total.inc();

        // Verify it was incremented
        let families = metrics.gather();
        let dlq_metric = families
            .iter()
            .find(|f| f.get_name() == "talos_dlq_entries_total");
        assert!(dlq_metric.is_some());
    }

    // Sanity-check that every crypto-invariant metric is actually
    // registered AND surfaces in the rendered Prometheus text format.
    // Catches typos in registry.register / series-name drift — a regression
    // here means the alerts in deploy/observability/alerts.yaml would
    // silently never fire.
    #[test]
    fn crypto_invariant_metrics_render() {
        let m = TalosMetrics::new().unwrap();

        m.kek_decrypt_failures_total
            .with_label_values(&["active"])
            .inc();
        m.kek_decrypt_failures_total
            .with_label_values(&["both"])
            .inc_by(2.0);
        m.memory_write_failures_total
            .with_label_values(&["crypto"])
            .inc();
        m.module_payload_encryption_failures_total
            .with_label_values(&["encrypt", "output"])
            .inc();
        m.actor_memory_orphaned_rows.set(3);
        m.module_execution_orphaned_rows.set(0);
        m.workflow_execution_orphaned_rows.set(0);
        m.dek_cache_size.set(42);

        let rendered = m.render_prometheus().expect("render");
        for name in [
            "talos_kek_decrypt_failures_total",
            "talos_memory_write_failures_total",
            "talos_module_payload_encryption_failures_total",
            "talos_actor_memory_orphaned_rows",
            "talos_module_execution_orphaned_rows",
            "talos_workflow_execution_orphaned_rows",
            "talos_dek_cache_size",
        ] {
            assert!(
                rendered.contains(name),
                "rendered output missing metric {name}\n--- output ---\n{rendered}"
            );
        }
        // Spot-check values land correctly.
        assert!(rendered.contains(r#"talos_kek_decrypt_failures_total{provider="active"} 1"#));
        assert!(rendered.contains(r#"talos_kek_decrypt_failures_total{provider="both"} 2"#));
        assert!(rendered.contains("talos_actor_memory_orphaned_rows 3"));
        assert!(rendered.contains("talos_dek_cache_size 42"));
    }

    // Crash-recovery outcome counter (durable execution, RFC 0003) must be
    // registered, pre-seeded at 0 for all three outcomes (so dashboards/alerts
    // have a series in steady state), and increment correctly. A regression
    // here means the crash-recovery observability surface silently disappears.
    #[test]
    fn crash_recovery_metric_seeded_and_increments() {
        let m = TalosMetrics::new().unwrap();

        // Pre-seeded at 0 from new() — present before any recovery runs.
        let rendered = m.render_prometheus().expect("render");
        for outcome in ["resumed", "failed", "reclaimed"] {
            assert!(
                rendered.contains(&format!(
                    "talos_crash_recovery_total{{outcome=\"{outcome}\"}} 0"
                )),
                "crash_recovery_total[{outcome}] not pre-seeded at 0\n{rendered}"
            );
        }

        // Increment behaves: counts accumulate per outcome label.
        m.crash_recovery_total.with_label_values(&["resumed"]).inc();
        m.crash_recovery_total
            .with_label_values(&["reclaimed"])
            .inc_by(3.0);
        let rendered = m.render_prometheus().expect("render");
        assert!(rendered.contains(r#"talos_crash_recovery_total{outcome="resumed"} 1"#));
        assert!(rendered.contains(r#"talos_crash_recovery_total{outcome="reclaimed"} 3"#));
        assert!(rendered.contains(r#"talos_crash_recovery_total{outcome="failed"} 0"#));
    }

    // set_global / global round-trip. One-shot semantics: subsequent
    // sets are no-ops (and crucially must not panic).
    #[test]
    fn global_metrics_oncelock_round_trip() {
        // If another test already initialised the global, the value will
        // reflect that — this test is side-effect-tolerant. We care that
        // global() returns Some AFTER set_global.
        let m = TalosMetrics::new().unwrap();
        set_global(m.clone());
        let fetched = global().expect("global registry installed");
        // Increment via global; verify via the local Arc.
        fetched.dek_cache_size.set(7);
        // Both references share the same underlying prometheus collectors.
        assert_eq!(m.dek_cache_size.get(), 7);
    }
}
