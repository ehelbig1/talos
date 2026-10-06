//! The SHAPE of everything the worker exports: each metric family's name and
//! type, and the label keys of each series.
//!
//! Recorded 2026-10-06 under opentelemetry 0.32 and identical under 0.33 (28
//! families). The exporter decides the final spelling — it appends `_total`,
//! splits a histogram into `_bucket` / `_sum` / `_count`, adds
//! `otel_scope_name` and the `target_info` family — so a new exporter release
//! can rename a series without a line of this crate changing. A renamed
//! series does not fail an alert or a dashboard: it silences it.
//!
//! `metrics::tests::exported_prometheus_names_are_stable_and_idle_seeds_at_zero`
//! pins the series a cold worker seeds. This pins the rest, which appear only
//! once something has been recorded.
//!
//! Its own test binary on purpose. The Prometheus registry is process-global,
//! and this test records on every instrument; inside the crate's unit-test
//! binary that would break the idle test above, which asserts that nothing
//! has been recorded. Here the registry is this test's alone, so the
//! comparison is exact in both directions: a family that disappears fails,
//! and so does one that appears.

use talos_worker_runtime::metrics::{
    get_prometheus_metrics, init_telemetry, InstanceCacheTier, LlmFailure, RuntimeMetrics,
};

const EXPECTED: [&str; 66] = [
    "SERIES talos_circuit_breaker_blocks_total {reason}",
    "SERIES talos_circuit_breaker_opens_total {transition}",
    "SERIES target_info {service_name,telemetry_sdk_language,telemetry_sdk_name,telemetry_sdk_version}",
    "SERIES wasm_approval_decided_total {decision,otel_scope_name}",
    "SERIES wasm_approval_requested_total {otel_scope_name}",
    "SERIES wasm_cache_hit_ratio {otel_scope_name}",
    "SERIES wasm_cache_hits_total {otel_scope_name}",
    "SERIES wasm_cache_misses_total {otel_scope_name}",
    "SERIES wasm_compilation_duration_ms_bucket {le,otel_scope_name}",
    "SERIES wasm_compilation_duration_ms_count {otel_scope_name}",
    "SERIES wasm_compilation_duration_ms_sum {otel_scope_name}",
    "SERIES wasm_errors_total {otel_scope_name,type}",
    "SERIES wasm_errors_trap_total {otel_scope_name}",
    "SERIES wasm_execution_duration_ms_bucket {le,otel_scope_name,status}",
    "SERIES wasm_execution_duration_ms_count {otel_scope_name,status}",
    "SERIES wasm_execution_duration_ms_sum {otel_scope_name,status}",
    "SERIES wasm_executions_cancelled_total {otel_scope_name}",
    "SERIES wasm_executions_preempted_total {otel_scope_name}",
    "SERIES wasm_executions_total {otel_scope_name,status}",
    "SERIES wasm_host_function_calls_total {function,otel_scope_name}",
    "SERIES wasm_host_function_duration_ms_bucket {function,le,otel_scope_name}",
    "SERIES wasm_host_function_duration_ms_count {function,otel_scope_name}",
    "SERIES wasm_host_function_duration_ms_sum {function,otel_scope_name}",
    "SERIES wasm_instance_cache_evictions_total {otel_scope_name,tier}",
    "SERIES wasm_instances_active {otel_scope_name}",
    "SERIES wasm_llm_duration_ms_bucket {le,otel_scope_name,provider}",
    "SERIES wasm_llm_duration_ms_count {otel_scope_name,provider}",
    "SERIES wasm_llm_duration_ms_sum {otel_scope_name,provider}",
    "SERIES wasm_llm_failures_total {otel_scope_name,outcome,provider}",
    "SERIES wasm_llm_gate_total {otel_scope_name,outcome}",
    "SERIES wasm_llm_queue_wait_ms_bucket {le,otel_scope_name}",
    "SERIES wasm_llm_queue_wait_ms_count {otel_scope_name}",
    "SERIES wasm_llm_queue_wait_ms_sum {otel_scope_name}",
    "SERIES wasm_llm_requests_total {otel_scope_name,provider}",
    "SERIES wasm_llm_token_usage_total {direction,otel_scope_name}",
    "SERIES wasm_quota_exceeded_total {metric,otel_scope_name}",
    "SERIES wasm_rate_limit_exceeded_total {function,otel_scope_name}",
    "SERIES wasm_retries_total {otel_scope_name,reason}",
    "TYPE talos_circuit_breaker_blocks_total counter",
    "TYPE talos_circuit_breaker_opens_total counter",
    "TYPE target_info gauge",
    "TYPE wasm_approval_decided_total counter",
    "TYPE wasm_approval_requested_total counter",
    "TYPE wasm_cache_hit_ratio gauge",
    "TYPE wasm_cache_hits_total counter",
    "TYPE wasm_cache_misses_total counter",
    "TYPE wasm_compilation_duration_ms histogram",
    "TYPE wasm_errors_total counter",
    "TYPE wasm_errors_trap_total counter",
    "TYPE wasm_execution_duration_ms histogram",
    "TYPE wasm_executions_cancelled_total counter",
    "TYPE wasm_executions_preempted_total counter",
    "TYPE wasm_executions_total counter",
    "TYPE wasm_host_function_calls_total counter",
    "TYPE wasm_host_function_duration_ms histogram",
    "TYPE wasm_instance_cache_evictions_total counter",
    "TYPE wasm_instances_active gauge",
    "TYPE wasm_llm_duration_ms histogram",
    "TYPE wasm_llm_failures_total counter",
    "TYPE wasm_llm_gate_total counter",
    "TYPE wasm_llm_queue_wait_ms histogram",
    "TYPE wasm_llm_requests_total counter",
    "TYPE wasm_llm_token_usage_total counter",
    "TYPE wasm_quota_exceeded_total counter",
    "TYPE wasm_rate_limit_exceeded_total counter",
    "TYPE wasm_retries_total counter",
];

#[test]
fn every_exported_family_keeps_its_name_type_and_label_keys() {
    init_telemetry().expect("telemetry initialises once in this binary");
    let m = RuntimeMetrics::new();
    // One measurement on every instrument, so nothing is absent for want of use.
    m.record_execution(12.0, "success");
    m.record_compilation(3.0, true);
    m.record_compilation(3.0, false);
    m.record_instance_cache_evictions(InstanceCacheTier::Minimal, 2);
    m.increment_active();
    m.decrement_active();
    m.record_retry("timeout");
    m.record_error("trap");
    m.record_rate_limit_exceeded("http");
    m.record_approval_requested();
    m.record_approval_decided("approved");
    m.record_llm_failure("ollama", LlmFailure::Cancelled);
    m.record_llm_request("ollama", 5.0);
    m.record_llm_tokens("prompt", 7);
    m.record_llm_gate("acquired", 1.0);
    m.record_execution_cancelled();
    m.record_execution_preempted();
    m.record_quota_exceeded("fuel");
    m.record_host_function_call("http::fetch", 2.0);

    let text = get_prometheus_metrics();
    let mut shape = std::collections::BTreeSet::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            shape.insert(format!("TYPE {rest}"));
        } else if !line.starts_with('#') && !line.is_empty() {
            let name = line.split(['{', ' ']).next().unwrap_or("");
            let mut keys: Vec<&str> = match (line.find('{'), line.find('}')) {
                (Some(open), Some(close)) => line[open + 1..close]
                    .split(',')
                    .filter_map(|pair| pair.split('=').next())
                    .collect(),
                _ => Vec::new(),
            };
            keys.sort_unstable();
            keys.dedup();
            shape.insert(format!("SERIES {name} {{{}}}", keys.join(",")));
        }
    }
    // `process_*` is the Linux-only process collector, not an instrument of
    // this crate; its families are the `prometheus` crate's to name.
    shape.retain(|line| {
        !line
            .split(' ')
            .nth(1)
            .is_some_and(|name| name.starts_with("process_"))
    });

    let expected: std::collections::BTreeSet<String> =
        EXPECTED.iter().map(|line| (*line).to_string()).collect();
    let gone: Vec<&String> = expected.difference(&shape).collect();
    let new: Vec<&String> = shape.difference(&expected).collect();
    assert!(
        gone.is_empty() && new.is_empty(),
        "the worker's exported metrics changed shape.\n\n\
         No longer exported (every alert and dashboard on these goes quiet):\n  {gone:#?}\n\n\
         Newly exported (add them here once they are meant):\n  {new:#?}"
    );
}
