#[cfg(test)]
mod tests {
    use crate::metrics::*;

    // ========================================================================
    // normalize_status tests
    // ========================================================================

    #[test]
    fn test_normalize_status_known_values() {
        assert_eq!(normalize_status("success"), "success");
        assert_eq!(normalize_status("error"), "error");
        assert_eq!(normalize_status("timeout"), "timeout");
        assert_eq!(normalize_status("retry_exhausted"), "retry_exhausted");
        assert_eq!(normalize_status("out_of_fuel"), "out_of_fuel");
        assert_eq!(normalize_status("trap"), "trap");
        assert_eq!(normalize_status("memory_limit"), "memory_limit");
    }

    #[test]
    fn test_normalize_status_unknown_defaults_to_other() {
        assert_eq!(normalize_status("unknown_status"), "other");
        assert_eq!(normalize_status("random"), "other");
        assert_eq!(normalize_status(""), "other");
    }

    // ========================================================================
    // normalize_error_type tests
    // ========================================================================

    #[test]
    fn test_normalize_error_type_known_values() {
        assert_eq!(normalize_error_type("timeout"), "timeout");
        assert_eq!(normalize_error_type("out_of_fuel"), "out_of_fuel");
        assert_eq!(normalize_error_type("trap"), "trap");
        assert_eq!(normalize_error_type("memory_limit"), "memory_limit");
        assert_eq!(normalize_error_type("runtime_error"), "runtime_error");
        assert_eq!(normalize_error_type("module_error"), "module_error");
        assert_eq!(
            normalize_error_type("retries_exhausted"),
            "retries_exhausted"
        );
        assert_eq!(normalize_error_type("network_error"), "network_error");
        assert_eq!(normalize_error_type("cache_error"), "cache_error");
    }

    #[test]
    fn test_normalize_error_type_unknown_defaults_to_other() {
        assert_eq!(normalize_error_type("custom_error"), "other");
        assert_eq!(normalize_error_type(""), "other");
    }

    // ========================================================================
    // normalize_retry_reason tests
    // ========================================================================

    #[test]
    fn test_normalize_retry_reason_known_values() {
        assert_eq!(normalize_retry_reason("transient_error"), "transient_error");
        assert_eq!(normalize_retry_reason("network_error"), "network_error");
        assert_eq!(normalize_retry_reason("timeout"), "timeout");
        assert_eq!(normalize_retry_reason("rate_limit"), "rate_limit");
        assert_eq!(
            normalize_retry_reason("service_unavailable"),
            "service_unavailable"
        );
    }

    #[test]
    fn test_normalize_retry_reason_unknown_defaults_to_other() {
        assert_eq!(normalize_retry_reason("some_reason"), "other");
    }

    // ========================================================================
    // normalize_rate_limit_function tests
    // ========================================================================

    #[test]
    fn test_normalize_rate_limit_function_known_values() {
        assert_eq!(normalize_rate_limit_function("http"), "http");
        assert_eq!(normalize_rate_limit_function("db"), "db");
        assert_eq!(normalize_rate_limit_function("messaging"), "messaging");
        assert_eq!(normalize_rate_limit_function("log"), "log");
        assert_eq!(normalize_rate_limit_function("fs"), "fs");
    }

    #[test]
    fn test_normalize_rate_limit_function_unknown_defaults_to_other() {
        assert_eq!(normalize_rate_limit_function("custom"), "other");
    }

    // ========================================================================
    // normalize_approval_decision tests
    // ========================================================================

    #[test]
    fn test_normalize_approval_decision_known_values() {
        assert_eq!(normalize_approval_decision("approved"), "approved");
        assert_eq!(normalize_approval_decision("denied"), "denied");
    }

    #[test]
    fn test_normalize_approval_decision_unknown_defaults_to_other() {
        assert_eq!(normalize_approval_decision("pending"), "other");
    }

    // ========================================================================
    // normalize_llm_provider tests
    // ========================================================================

    #[test]
    fn test_normalize_llm_provider_known_values() {
        assert_eq!(normalize_llm_provider("anthropic"), "anthropic");
        assert_eq!(normalize_llm_provider("openai"), "openai");
        assert_eq!(normalize_llm_provider("gemini"), "gemini");
    }

    #[test]
    fn test_normalize_llm_provider_unknown_defaults_to_other() {
        assert_eq!(normalize_llm_provider("ollama"), "other");
    }

    // ========================================================================
    // normalize_token_direction tests
    // ========================================================================

    #[test]
    fn test_normalize_token_direction_known_values() {
        assert_eq!(normalize_token_direction("input"), "input");
        assert_eq!(normalize_token_direction("output"), "output");
    }

    #[test]
    fn test_normalize_token_direction_unknown_defaults_to_other() {
        assert_eq!(normalize_token_direction("total"), "other");
    }

    // ========================================================================
    // normalize_quota_metric tests
    // ========================================================================

    #[test]
    fn test_normalize_quota_metric_known_values() {
        assert_eq!(normalize_quota_metric("http_calls"), "http_calls");
        assert_eq!(normalize_quota_metric("db_queries"), "db_queries");
        assert_eq!(
            normalize_quota_metric("messaging_publishes"),
            "messaging_publishes"
        );
        assert_eq!(normalize_quota_metric("fs_bytes"), "fs_bytes");
        assert_eq!(normalize_quota_metric("log_messages"), "log_messages");
        assert_eq!(normalize_quota_metric("memory_bytes"), "memory_bytes");
    }

    #[test]
    fn test_normalize_quota_metric_unknown_defaults_to_other() {
        assert_eq!(normalize_quota_metric("custom_metric"), "other");
    }

    // ========================================================================
    // normalize_host_function_name tests
    // ========================================================================

    #[test]
    fn test_normalize_host_function_name_known_values() {
        assert_eq!(normalize_host_function_name("http::fetch"), "http::fetch");
        assert_eq!(
            normalize_host_function_name("db::execute_query"),
            "db::execute_query"
        );
        assert_eq!(
            normalize_host_function_name("messaging::publish"),
            "messaging::publish"
        );
        assert_eq!(
            normalize_host_function_name("messaging::subscribe"),
            "messaging::subscribe"
        );
        assert_eq!(normalize_host_function_name("cache::get"), "cache::get");
        assert_eq!(normalize_host_function_name("cache::set"), "cache::set");
        assert_eq!(
            normalize_host_function_name("cache::delete"),
            "cache::delete"
        );
        assert_eq!(
            normalize_host_function_name("secrets::get_secret"),
            "secrets::get_secret"
        );
        assert_eq!(normalize_host_function_name("files::read"), "files::read");
        assert_eq!(normalize_host_function_name("files::write"), "files::write");
        assert_eq!(
            normalize_host_function_name("graphql::execute"),
            "graphql::execute"
        );
        assert_eq!(
            normalize_host_function_name("llm::complete"),
            "llm::complete"
        );
        assert_eq!(normalize_host_function_name("llm::stream"), "llm::stream");
        assert_eq!(normalize_host_function_name("email::send"), "email::send");
        assert_eq!(normalize_host_function_name("logging::log"), "logging::log");
    }

    #[test]
    fn test_normalize_host_function_name_unknown_defaults_to_other() {
        assert_eq!(normalize_host_function_name("custom::function"), "other");
        assert_eq!(normalize_host_function_name(""), "other");
    }

    // ========================================================================
    // Exported Prometheus name pinning + idle-seed
    // ========================================================================

    /// The dot→underscore + `_total` mapping is a PROPERTY OF THE EXPORTER,
    /// not of anything in this repo, and until 2026-08-02 nothing checked it.
    /// `opentelemetry-prometheus` appends `_total` to every monotonic counter
    /// unconditionally, so the three instruments that used to be named
    /// `wasm.*.total` were exported as `wasm_*_total_total` — which made FIVE
    /// of the eleven alert rules in `observability/rules/alerts.yml` select on a
    /// name the worker could not emit under any workload (two more were
    /// unfireable for unrelated reasons — the cache rule was missing the
    /// exporter's `_total`, and `wasm_memory_used_bytes` had no instrument at
    /// all — for seven total; `observability/rules/alerts.yml`'s header carries the
    /// full breakdown). A behavioural test that only asserted "the counter
    /// went up" would not have caught it; only the rendered exposition text
    /// can.
    ///
    /// This test is the ground truth structural lint check 65(c) trusts when
    /// it derives an exported `wasm_*` name from an OTEL declaration. If the
    /// exporter's suffix rule ever changes under a dependency bump, this
    /// fails here rather than silently unfiring every WASM alert in
    /// production.
    ///
    /// It also asserts the idle seed: on a cold process that has executed
    /// NOTHING, the seeded series must be PRESENT and 0. Absent and zero are
    /// different, and the whole point of `seed_zero_series` is to make the
    /// idle case the second one.
    #[test]
    fn exported_prometheus_names_are_stable_and_idle_seeds_at_zero() {
        // Installs the global meter provider over `prometheus::default_registry()`.
        // Safe to do once per test binary; no other test in this module touches it.
        init_telemetry().expect("telemetry init");

        // Cold process: construct the metrics and record NOTHING.
        let _m = RuntimeMetrics::new();
        let cold = get_prometheus_metrics();

        // ── the idle seed ────────────────────────────────────────────────
        for expected in [
            r#"wasm_executions_total{status="success""#,
            r#"wasm_executions_total{status="error""#,
            r#"wasm_executions_total{status="retry_exhausted""#,
            "wasm_cache_hits_total{",
            "wasm_cache_misses_total{",
        ] {
            assert!(
                cold.contains(expected),
                "idle worker must EXPORT {expected} (at 0), not omit it — \
                 an absent series silences `rate(...) == 0` alerts.\n{cold}"
            );
        }
        for line in cold.lines() {
            if line.starts_with("wasm_executions_total{") || line.starts_with("wasm_cache_") {
                assert!(
                    line.ends_with(" 0"),
                    "seeded series must read 0 on a cold process, got: {line}"
                );
            }
        }
        // Nothing has run, so the started-side counter must NOT have been
        // seeded into existence: it would claim a dispatch that never happened.
        assert!(
            !cold.contains("wasm_executions_started_total"),
            "wasm.executions.started is deliberately unseeded; a 0 there would \
             imply a dispatch path was observed when none has run yet:\n{cold}"
        );

        // ── the exported-name mapping ────────────────────────────────────
        let m = RuntimeMetrics::new();
        m.record_execution(1.0, "success");
        m.record_compilation(1.0, true);
        m.record_compilation(2.0, false);
        m.increment_active();
        m.record_retry("transient_error");
        m.record_error("timeout");
        // Written directly on the pub field rather than through a helper,
        // because that is exactly how the dispatch entry point does it
        // (`runtime.rs`: `metrics.total_executions.add(1, &[])`). Without
        // this the started-side counter is never touched, so the name
        // assertion below has nothing to observe and fails — which is not a
        // naming bug but a gap in what this block exercises.
        m.total_executions.add(1, &[]);
        let out = get_prometheus_metrics();

        // Exactly the spellings observability/rules/alerts.yml and the Grafana
        // dashboards select on. A counter declared `wasm.x` exports
        // `wasm_x_total`; a histogram declared `wasm.x` exports
        // `wasm_x_bucket`/`_sum`/`_count`; an up/down counter and a gauge
        // export their name unchanged.
        for expected in [
            "wasm_executions_total{",             // u64_counter  wasm.executions
            "wasm_executions_started_total{",     // u64_counter  wasm.executions.started
            "wasm_errors_total{",                 // u64_counter  wasm.errors
            "wasm_retries_total{",                // u64_counter  wasm.retries
            "wasm_cache_hits_total{",             // u64_counter  wasm.cache.hits
            "wasm_cache_misses_total{",           // u64_counter  wasm.cache.misses
            "wasm_execution_duration_ms_bucket{", // f64_histogram wasm.execution.duration_ms
            "wasm_execution_duration_ms_sum{",
            "wasm_execution_duration_ms_count{",
            "wasm_instances_active{", // i64_up_down_counter wasm.instances.active
            "wasm_cache_hit_ratio{",  // f64_gauge    wasm.cache.hit_ratio
        ] {
            assert!(
                out.contains(expected),
                "expected exported series {expected} — alerts and dashboards \
                 select on this exact spelling.\n{out}"
            );
        }

        // Every exported series also carries `otel_scope_name` = the meter
        // name. Confirmed 2026-08-02 by scraping a real running process over
        // authenticated HTTP, not inferred from the exporter's source. It is
        // pinned here because it is a LABEL the alert rules and
        // `observability/alerts_test.yml` have to model: `LowCacheHitRate`'s
        // `a / (a + b)` matches on identical label sets, so both cache legs
        // sharing one meter is load-bearing — split them across two meters and
        // the division silently yields an empty vector.
        assert!(
            out.contains(r#"otel_scope_name="talos-wasm-runtime""#),
            "exported series must carry the meter's otel_scope_name label; the \
             alert-rule tests model it\n{out}"
        );

        // The regression that motivated the rename: NO double suffix.
        for forbidden in [
            "wasm_executions_total_total",
            "wasm_errors_total_total",
            "wasm_retries_total_total",
        ] {
            assert!(
                !out.contains(forbidden),
                "instrument name still carries a redundant `total` component; \
                 the exporter appends its own, producing {forbidden}, which no \
                 alert rule selects on.\n{out}"
            );
        }

        // ── the exported `le=` set ───────────────────────────────────────
        // The bucket BOUNDARIES are as load-bearing as the metric NAME, and
        // for the same reason: `SlowWASMExecution` and `VerySlowWASMExecution`
        // select fixed `le=` values, so a boundary that disappears takes its
        // rule with it. `WASMLatencyBucketMissing` is the runtime net for
        // that; this is the build-time one, and it is strictly earlier.
        //
        // Asserted against the exported text rather than against the constant
        // so it also covers the exporter's float FORMATTING — Prometheus `le`
        // labels are string-matched, and `le="10000"` and `le="10000.0"` are
        // different selectors to a rule that names one of them.
        let exported_les: std::collections::BTreeSet<&str> = out
            .lines()
            .filter(|l| l.starts_with("wasm_execution_duration_ms_bucket{"))
            .filter_map(|l| l.split("le=\"").nth(1))
            .filter_map(|rest| rest.split('"').next())
            .collect();
        let expected_les: std::collections::BTreeSet<String> =
            crate::metrics::EXECUTION_DURATION_BOUNDARIES_MS
                .iter()
                .map(|b| format!("{b}"))
                .chain(std::iter::once("+Inf".to_string()))
                .collect();
        let expected_refs: std::collections::BTreeSet<&str> =
            expected_les.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            exported_les, expected_refs,
            "exported bucket boundaries drifted from \
             EXECUTION_DURATION_BOUNDARIES_MS. Every `le=` selector in \
             observability/rules/alerts.yml and every promtool fixture in \
             observability/alerts_test.yml is coupled to this set."
        );

        // Named individually, because these two are not merely PRESENT — they
        // are the exact values `observability/rules/alerts.yml` selects on.
        // Changing either one re-calibrates an alert threshold, which is a
        // different decision from re-bucketing a histogram and must not ride
        // along inside one.
        //
        // ASSERTED AGAINST `exported_les`, NOT AGAINST `out`. The first
        // version of this loop did `out.contains(r#"le="10000""#)` over the
        // WHOLE exposition, and that assertion was VACUOUS — proven by
        // mutation on 2026-08-04: delete `10000.0` from
        // EXECUTION_DURATION_BOUNDARIES_MS, rebuild, and the test still
        // passed. Two reasons compounded. (1) `exported_les` and
        // `expected_les` are BOTH derived from the constant, so they agree
        // with each other however the constant changes — that assert_eq
        // catches exporter FORMATTING drift, which is what it is for, and
        // cannot catch a boundary being removed. (2) THREE sibling histograms
        // — `wasm_compilation_duration_ms`, `wasm_llm_duration_ms`,
        // `wasm_host_function_duration_ms` — are still on the SDK defaults and
        // therefore still export `le="2500"` and `le="10000"` of their own, so
        // the substring was satisfied by a metric no alert rule selects on.
        // Verified on a live scrape: all four names carry both labels.
        //
        // The whole point of this pin is to fail `cargo test` instead of
        // waiting 15 minutes for `WASMLatencyBucketMissing` to page, so an
        // assertion that cannot fail is worse than none — it is a gate that
        // reports coverage it does not have.
        for alert_selected in ["2500", "10000"] {
            assert!(
                exported_les.contains(alert_selected),
                "wasm_execution_duration_ms has no le=\"{alert_selected}\" \
                 bucket. That boundary is selected BY NAME in \
                 observability/rules/alerts.yml (SlowWASMExecution / \
                 VerySlowWASMExecution); removing it silences that rule with \
                 no error anywhere. Exported set: {exported_les:?}\n{out}"
            );
        }
    }

    /// The SDK's failure mode for bad boundaries is a NO-OP instrument plus an
    /// internal log line — not a build error and not a startup panic. A
    /// histogram that silently stops recording is indistinguishable from a
    /// worker that is not executing, so the preconditions are asserted here
    /// where they fail loudly.
    #[test]
    fn execution_duration_boundaries_are_valid() {
        let b = crate::metrics::EXECUTION_DURATION_BOUNDARIES_MS;
        // NOT "would fall back to defaults" — that was wrong and is worth
        // correcting rather than deleting, because the wrong version made an
        // empty set sound harmless. An explicitly empty boundary vec means NO
        // bucket information at all: the histogram exports `+Inf` only, which
        // is strictly WORSE than the SDK defaults this constant replaced.
        assert!(
            !b.is_empty(),
            "empty boundaries export a +Inf bucket and nothing else — no \
             quantile, no le= selector, and both latency rules go silent"
        );
        assert!(
            b.iter().all(|v| v.is_finite()),
            "NaN/±Inf boundaries make the SDK return a no-op instrument: {b:?}"
        );
        assert!(
            b.windows(2).all(|w| w[0] < w[1]),
            "boundaries must be strictly ascending (sorted, no duplicates): {b:?}"
        );
        // The justification here is EMPIRICAL, not structural, and the
        // difference is not pedantry: an earlier version of this message said
        // a `le=0` bucket "can never be non-empty" because duration_ms is an
        // `as_millis()` truncation. That inverts the mechanism. Truncation
        // sends every sub-millisecond execution to exactly `0.0`, and the
        // lowest bucket is `(-inf, 0]`, which INCLUDES `0.0` — so truncation
        // is precisely what would POPULATE `le=0`. It is empty because nothing
        // on this workload has ever completed in under 1 ms (0 observations
        // across 15 d), which is a fact about the workload and could change.
        assert!(
            b[0] > 0.0,
            "`le=0` counted zero executions over 15 d, so it is a series \
             permanently equal to its neighbour on this workload. (It is \
             reachable in principle: as_millis() truncation records a \
             sub-millisecond execution as exactly 0.0, which lands in it.)"
        );
        // The top bound is the worker's DEFAULT per-node wall-clock timeout
        // (`WASM_EXECUTION_TIMEOUT_SECS`, default 120s) — a default, not a
        // clamp. A node with an explicit `timeout_secs` runs past it in a
        // single attempt, so overflow means EITHER accumulated retries OR a
        // raised per-node timeout. The slowest execution actually observed on
        // the dev stack was 81.9 s; a top bound below that is the defect this
        // constant exists to fix.
        assert!(
            *b.last().expect("non-empty") >= 120_000.0,
            "top finite bound must cover the 120s per-node timeout: {b:?}"
        );
    }
}
