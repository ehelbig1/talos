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

/// Record a terminal workflow-execution outcome on the process-global
/// `talos_workflow_executions_total{status}` counter. Inert when metrics
/// aren't wired (unit tests, any process without `set_global`) — never
/// unwraps, mirroring [`global`]'s contract.
///
/// Called from the two terminal-write chokepoints
/// (`mark_execution_completed` → `"success"`, `mark_execution_failed` →
/// `"failure"`) so every finalizing caller (trigger / retry / replay /
/// crash-recovery / GraphQL / MCP) feeds the counter without each site
/// remembering to. This is the metric the TalosWorkflowFailureRateHigh
/// alert fires on — before this wiring the counter was registered but
/// never incremented (dead), so any alert on it would never have fired.
pub fn record_workflow_outcome(status: &str) {
    if let Some(m) = global() {
        m.workflow_executions_total
            .with_label_values(&[status])
            .inc();
    }
}

/// Global metrics registry and collectors
pub struct TalosMetrics {
    pub registry: Registry,

    // Webhook metrics
    pub webhook_requests_total: CounterVec,
    pub webhook_request_duration_seconds: HistogramVec,
    pub webhook_dlq_drops_total: Counter,

    // Authentication metrics.
    //
    // `auth_attempts_total` / `auth_failures_total` are the denominator and
    // numerator of the `TalosControllerHighErrorRate` alert. Emitted for
    // INTERACTIVE logins only — `method=password` (`talos_auth::AuthService::
    // login`) and `method=oauth` (the controller's `oauth_callback_handler`).
    // API-key validation is deliberately excluded: it runs on every GraphQL
    // request, so folding it into the same `sum(rate(...))` would swamp the
    // interactive population and leave a credential-stuffing burst unable to
    // move the ratio — an alert that is technically live but still cannot
    // fire. `api_key_validations_total` below is that surface's own series
    // (currently unwired; no alert references it).
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

    // ---- Detector metrics (2026-08) ----
    //
    // Each of the five below existed as a WARN/ERROR log line ONLY. Every
    // alert this platform ships is metric-based, so a log-only detector is a
    // signal nothing can consume — the same defect as a signal never emitted.
    // Adding the counter is what makes the detector page-able.
    //
    // DO NOT collapse these into a shared `warn_and_count!` macro. A macro
    // body would contain the literal `.field….inc()` for every metric it can
    // touch, so all of them would read as LIVE to structural check 58 from one
    // definition site — re-blinding the lint in exactly the way #620 just
    // fixed. If a future author does build such a helper, check 58 must first
    // be taught to require an INVOCATION naming the field rather than a
    // textual match.
    /// WASM log lines discarded because they could not be routed to any
    /// execution row. Labels: `kind=no_execution_row|unparseable_id`, a
    /// closed set of `&'static str` — never the guest-authored message body,
    /// never the execution id (an orphaned line may carry module output, and
    /// a per-execution label would be unbounded cardinality).
    pub wasm_log_orphaned_total: CounterVec,
    /// `module_executions` start-row INSERT failures at the single
    /// `PostgresModuleExecutionStore::record_started` chokepoint. The upstream
    /// CAUSE of `wasm_log_orphaned_total{kind="no_execution_row"}`, and
    /// independently it means `get_execution_logs` / `get_node_io` / cost
    /// attribution are quietly missing rows.
    pub module_execution_record_started_failures_total: Counter,
    /// WORM audit-ledger verification failures. Labels:
    /// `stage=event|chain` — `event` is the inline per-message
    /// authenticity/integrity check at ingest (the message is quarantined,
    /// never persisted); `chain` is the offline hash-chain sweep over a
    /// completed execution's full ordered record set. Either means the
    /// compliance artifact is void for that execution.
    pub audit_verification_failures_total: CounterVec,
    /// Worker-key trust-on-first-use conflicts at the self-registration
    /// endpoint: a `worker_id` presented a key that is not its bound
    /// identity. In-fleet impersonation, or an operator rotating off the
    /// managed path. UNLABELLED on purpose — `worker_id` and the submitted
    /// key are both caller-supplied at a network endpoint, so neither may
    /// become a label (unbounded cardinality, attacker-driven).
    pub worker_key_tofu_conflicts_total: Counter,
    /// Number of distinct `worker_id`s with an ACTIVE `worker_identities` row
    /// whose reported build provably differs from this controller's. A GAUGE,
    /// recomputed from a query each sweep (always `set`, never `inc`/`dec`) so a
    /// worker catching up, or having its key deactivated, lowers it. A counter
    /// would be wrong at both ends: it would fire on every rolling deploy AND go
    /// quiet while a fleet stayed skewed.
    ///
    /// ACTIVE means "row not deactivated", NOT "process running": nothing reaps
    /// the row of a pod that is gone, and `last_seen_at` is boot-only so no age
    /// filter can tell the two apart. On a fleet whose `worker_id` is the pod
    /// name (the chart default), retired pods keep this above zero after a
    /// controller upgrade until an operator deactivates their keys. See
    /// `controller::bootstrap::background::publish_worker_build_skew`.
    ///
    /// "Unverifiable" workers are NOT counted here (absence of evidence is
    /// not evidence of skew — #578).
    pub worker_build_skew_workers: IntGauge,

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
    /// Alerts auto-resolved by a source-signaled recovery
    /// (`status_event: "resolved"` in the __ops_alert__ envelope).
    pub ops_alert_auto_resolved_total: Counter,
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
            // Emitted values: password | oauth. See the struct-field comment
            // for why api_key is deliberately not in this population.
            &["method"],
        )?;
        registry.register(Box::new(auth_attempts_total.clone()))?;
        // Pre-seed the two `method` values that are actually emitted
        // (`talos_auth::AUTH_METHOD_PASSWORD` / `_OAUTH`), so a controller
        // that has served no interactive login still EXPORTS the series at 0
        // instead of omitting it. A `CounterVec` emits nothing at all until a
        // label set is first touched, which makes "detector present and
        // quiet" indistinguishable from "detector deleted" on a healthy
        // stack — the exact ambiguity that let five alerted CounterVecs here
        // sit unexercised. `api_key` is deliberately NOT seeded: it is not in
        // this population (see the talos-auth header for why folding it in
        // would make TalosControllerHighErrorRate unfireable in practice).
        //
        // Note precisely what this proves and what it does not: a present
        // denominator shows the auth counters were registered in THIS
        // process. It does not show the failure leg is still wired — that is
        // what the talos-auth unit tests driving the production login path
        // are for.
        for method in ["password", "oauth"] {
            auth_attempts_total.with_label_values(&[method]).inc_by(0.0);
        }

        let auth_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_auth_failures_total",
                "Total number of authentication failures",
            ),
            // Emitted reasons are a closed literal set owned by the emitting
            // crate — see the `AUTH_REASON_*` constants in `talos-auth`.
            // Never a username, IP, or key id: this endpoint is scrapeable
            // and the label set must stay bounded.
            &["method", "reason"],
        )?;
        registry.register(Box::new(auth_failures_total.clone()))?;
        // DELIBERATELY NOT PRE-SEEDED, unlike its denominator above. The
        // `reason` values are a closed set of `&'static str` constants, but
        // the (method, reason) PRODUCT is not a valid population: only 9 of
        // the 16 pairs have an emitting call site (`unknown_user`, `locked`,
        // `lockout_triggered`, `invalid_password` are password-only;
        // `provider_error`, `csrf_state`, `link_failed` are oauth-only), and
        // seeding a pair nothing writes would imply a wired signal that does
        // not exist. Encoding the real pairing here would also mean copying
        // talos-auth's constants across a dependency edge that only points
        // the other way (talos-auth depends on this crate), so the two could
        // drift silently. Absence of a failure series is the correct
        // non-alerting answer anyway — see the TalosControllerHighErrorRate
        // comment in deploy/helm/talos/files/alerts.yaml.

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
        // Pre-seed the two terminal outcomes the finalizers write (success /
        // failure) at 0 — same reasoning as crash_recovery_total below: the
        // series must exist in steady state so `rate()` in the
        // TalosWorkflowFailureRateHigh alert (deploy/helm files/alerts.yaml)
        // has something to reference before the first failure. `timeout` /
        // `cancelled` are deliberately NOT seeded: nothing increments them yet
        // (the scheduler writes those states via a raw UPDATE), so seeding
        // them would imply a wired signal that doesn't exist.
        for outcome in ["success", "failure"] {
            workflow_executions_total
                .with_label_values(&[outcome])
                .inc_by(0.0);
        }

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

        // ---- Detector metrics (2026-08) ----
        let wasm_log_orphaned_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_wasm_log_orphaned_total",
                "WASM log lines discarded because they could not be routed to \
                 any execution row. Labels: kind=no_execution_row|unparseable_id. \
                 Non-zero means a dispatch path is minting execution ids without \
                 recording a row — those executions' logs are lost.",
            ),
            &["kind"],
        )?;
        registry.register(Box::new(wasm_log_orphaned_total.clone()))?;
        // Pre-seed both kinds at 0, same reasoning as crash_recovery_total: the
        // expected steady state is zero, so without seeding the series would be
        // ABSENT and `increase(...[15m]) > 0` would have nothing to reference
        // until the first incident. Seeding at 0 also lets a dashboard show
        // "detector present and quiet" rather than "detector missing".
        for kind in ["no_execution_row", "unparseable_id"] {
            wasm_log_orphaned_total
                .with_label_values(&[kind])
                .inc_by(0.0);
        }

        let module_execution_record_started_failures_total = Counter::new(
            "talos_module_execution_record_started_failures_total",
            "Failures writing the module_executions start row at the \
             PostgresModuleExecutionStore::record_started chokepoint. Non-fatal \
             by design, so the execution proceeds — but its row is missing, its \
             WASM logs orphan, and get_execution_logs / get_node_io / cost \
             attribution silently under-report.",
        )?;
        registry.register(Box::new(
            module_execution_record_started_failures_total.clone(),
        ))?;

        let audit_verification_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_audit_verification_failures_total",
                "WORM audit-ledger verification failures. Labels: \
                 stage=event|chain. stage=event is the inline per-message check \
                 at ingest (message quarantined, not persisted); stage=chain is \
                 the offline hash-chain sweep over a completed execution. Either \
                 is positive tamper/corruption evidence.",
            ),
            &["stage"],
        )?;
        registry.register(Box::new(audit_verification_failures_total.clone()))?;
        // Seeded for the same reason as the orphan counter above — the CRITICAL
        // alert on this series must have something to reference in steady state.
        for stage in ["event", "chain"] {
            audit_verification_failures_total
                .with_label_values(&[stage])
                .inc_by(0.0);
        }

        let worker_key_tofu_conflicts_total = Counter::new(
            "talos_worker_key_tofu_conflicts_total",
            "Worker self-registration refusals where the presented key is not \
             the worker_id's bound trust-on-first-use identity. Possible \
             in-fleet impersonation; legitimate rotation goes through the \
             operator CLI or a worker_id-bound provisioning token.",
        )?;
        registry.register(Box::new(worker_key_tofu_conflicts_total.clone()))?;

        let worker_build_skew_workers = IntGauge::new(
            "talos_worker_build_skew_workers",
            "Distinct worker_ids with an ACTIVE worker_identities row whose \
             build PROVABLY differs from this controller's (different commit \
             sha, or -dirty on one side only). Recomputed each sweep, so it \
             falls back to 0 once the fleet converges OR the stale rows are \
             deactivated — ACTIVE means 'row not deactivated', not 'process \
             running', and nothing reaps the row of a departed pod. Workers \
             that report no usable sha are 'unverifiable' and are NOT counted.",
        )?;
        registry.register(Box::new(worker_build_skew_workers.clone()))?;

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
        // Seed only the two `provider` values with a live emitting site:
        // `active` and `both`, both in `SecretsManager::decrypt_dek`. The
        // description's third value, `legacy`, has NO emitter anywhere in the
        // workspace — a total legacy-provider failure is reported as `both`.
        // Seeding `legacy` would put a permanent flat 0 on a dashboard for a
        // condition nothing can ever report, which reads as "watched and
        // healthy" rather than "not watched".
        for provider in ["active", "both"] {
            kek_decrypt_failures_total
                .with_label_values(&[provider])
                .inc_by(0.0);
        }

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
        // Closed set, and every value has a live emitter: the label comes
        // from `MemoryWriteError::metric_label()`, whose four variants are
        // exhaustively matched at the two `__memory_write__` hook sites in
        // talos-engine. Note the description above lists only three — the
        // catch-all `other` was added to the type without updating it; the
        // seed follows the CODE, which is what actually emits.
        for reason in ["crypto", "db", "validation", "other"] {
            memory_write_failures_total
                .with_label_values(&[reason])
                .inc_by(0.0);
        }

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

        let ops_alert_auto_resolved_total = Counter::new(
            "talos_ops_alert_auto_resolved_total",
            "ops_alerts rows resolved by a status_event: 'resolved' signal \
             from the ingest pipeline (source-reported recovery, e.g. a \
             Cloud Monitoring incident closing).",
        )?;
        registry.register(Box::new(ops_alert_auto_resolved_total.clone()))?;

        let module_payload_encryption_failures_total = CounterVec::new(
            prometheus::Opts::new(
                "talos_module_payload_encryption_failures_total",
                "module_executions payload encrypt/decrypt failures. \
                 Labels: op=encrypt|decrypt, stage=input|output|trigger_metadata.",
            ),
            &["op", "stage"],
        )?;
        registry.register(Box::new(module_payload_encryption_failures_total.clone()))?;
        // All six combinations are reachable, so all six are seeded:
        // `encrypt_payload_bundle` loops over all three `PayloadSlot`s and
        // `decrypt_payload_slot` is called for each of them, and both wrap
        // their failures through `inc_payload_crypto_failure`. Cardinality is
        // fixed at 6 by construction (both labels are `&'static str` from
        // closed sets) — the same bound that crate's own doc comment states.
        for op in ["encrypt", "decrypt"] {
            for stage in ["input", "output", "trigger_metadata"] {
                module_payload_encryption_failures_total
                    .with_label_values(&[op, stage])
                    .inc_by(0.0);
            }
        }

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
            wasm_log_orphaned_total,
            module_execution_record_started_failures_total,
            audit_verification_failures_total,
            worker_key_tofu_conflicts_total,
            worker_build_skew_workers,
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
            ops_alert_auto_resolved_total,
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

    /// Absence is not zero. A `CounterVec` emits NOTHING until some label set
    /// is first touched, so on a healthy controller that has had no auth
    /// traffic and no crypto failure, four of the five alerted CounterVecs
    /// were simply missing from `/metrics/prometheus` — indistinguishable
    /// from the wiring having been deleted. Pre-seeding the combinations that
    /// have a live emitter makes idle read `0` instead.
    ///
    /// This test asserts the seeds on a FRESH registry with nothing recorded,
    /// which is the state that matters (`crypto_invariant_metrics_render`
    /// above increments first, so it cannot see this).
    #[test]
    fn alerted_counter_vecs_are_seeded_at_zero_on_a_cold_registry() {
        let m = TalosMetrics::new().unwrap();
        let rendered = m.render_prometheus().expect("render");

        for expected in [
            r#"talos_auth_attempts_total{method="password"} 0"#,
            r#"talos_auth_attempts_total{method="oauth"} 0"#,
            r#"talos_kek_decrypt_failures_total{provider="active"} 0"#,
            r#"talos_kek_decrypt_failures_total{provider="both"} 0"#,
            r#"talos_memory_write_failures_total{reason="crypto"} 0"#,
            r#"talos_memory_write_failures_total{reason="db"} 0"#,
            r#"talos_memory_write_failures_total{reason="validation"} 0"#,
            r#"talos_memory_write_failures_total{reason="other"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="encrypt",stage="input"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="encrypt",stage="output"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="encrypt",stage="trigger_metadata"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="decrypt",stage="input"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="decrypt",stage="output"} 0"#,
            r#"talos_module_payload_encryption_failures_total{op="decrypt",stage="trigger_metadata"} 0"#,
        ] {
            assert!(
                rendered.contains(expected),
                "cold registry must EXPORT `{expected}` — an absent series is \
                 not a zero one, and every alert built on these reads absence \
                 as 'no match'\n--- output ---\n{rendered}"
            );
        }

        // The two deliberate non-seeds, asserted so a later "tidy-up" that
        // seeds them has to argue with a test rather than slip through.
        assert!(
            !rendered.contains("talos_auth_failures_total{"),
            "talos_auth_failures_total is deliberately unseeded: only 9 of its \
             16 (method, reason) pairs have an emitter, and seeding a pair \
             nothing writes implies a signal that does not exist\n{rendered}"
        );
        assert!(
            !rendered.contains(r#"provider="legacy""#),
            "provider=\"legacy\" has no emitting site anywhere in the \
             workspace; a flat 0 there would read as 'watched' when it is \
             not\n{rendered}"
        );
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

    // workflow_executions_total must be pre-seeded at 0 for success+failure
    // (so the TalosWorkflowFailureRateHigh alert's rate() has a series in
    // steady state) and increment per status label. Before this wiring the
    // counter was registered but never incremented — a dead metric that made
    // any alert on it silently un-fireable.
    #[test]
    fn workflow_executions_metric_seeded_and_increments() {
        let m = TalosMetrics::new().unwrap();
        let rendered = m.render_prometheus().expect("render");
        for status in ["success", "failure"] {
            assert!(
                rendered.contains(&format!(
                    "talos_workflow_executions_total{{status=\"{status}\"}} 0"
                )),
                "workflow_executions_total[{status}] not pre-seeded at 0\n{rendered}"
            );
        }
        m.workflow_executions_total
            .with_label_values(&["failure"])
            .inc();
        m.workflow_executions_total
            .with_label_values(&["success"])
            .inc_by(3.0);
        let rendered = m.render_prometheus().expect("render");
        assert!(rendered.contains(r#"talos_workflow_executions_total{status="failure"} 1"#));
        assert!(rendered.contains(r#"talos_workflow_executions_total{status="success"} 3"#));
    }

    // record_workflow_outcome is inert (no panic) when metrics aren't wired —
    // the finalizers call it unconditionally, and unit tests / any process
    // without set_global must not blow up.
    #[test]
    fn record_workflow_outcome_is_inert_without_global() {
        // Does not panic even though set_global may not have run in this test
        // binary. (If a sibling test already set the global, this still just
        // increments harmlessly.)
        super::record_workflow_outcome("failure");
        super::record_workflow_outcome("success");
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
