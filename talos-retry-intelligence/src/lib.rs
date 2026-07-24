//! Automatic retry intelligence: learns from execution history to classify errors
//! as transient vs permanent and suggest optimal retry policies.

use anyhow::Result;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

/// Error classification derived from historical execution data.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorClassification {
    pub error_type: String,
    pub occurrence_count: i64,
    pub retry_success_count: i64,
    pub retry_success_rate: f64,
    pub is_transient: bool,
    pub recommended_action: String,
}

/// Retry policy suggestion for a specific module.
#[derive(Debug, Clone, Serialize)]
pub struct RetryPolicySuggestion {
    pub module_name: String,
    pub current_max_retries: i32,
    pub suggested_max_retries: i32,
    pub suggested_backoff_ms: i64,
    pub reason: String,
    pub error_breakdown: Vec<ErrorClassification>,
}

/// Failure diagnosis for a workflow.
#[derive(Debug, Serialize)]
pub struct FailureDiagnosis {
    pub workflow_id: Uuid,
    pub period_hours: i64,
    pub total_executions: i64,
    pub failed_executions: i64,
    pub failure_rate_pct: f64,
    pub per_node_breakdown: Vec<NodeFailureBreakdown>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NodeFailureBreakdown {
    pub node_label: String,
    pub total_runs: i64,
    pub failures: i64,
    pub failure_rate_pct: f64,
    pub top_error_types: Vec<ErrorClassification>,
}

/// Classify an error message into a category.
///
/// MCP-444: `database_transient` is matched BEFORE the generic
/// `database_error` so true transient DB conditions (deadlock,
/// serialization failure, lock contention) keep their
/// retry-on-transient semantics. The generic `database_error` class is
/// reserved for deterministic failures — syntax errors, constraint
/// violations, permission denied, relation-does-not-exist. Pre-fix,
/// every sqlx error message containing the substring "sql", "query",
/// or "database" was classified `database_error` AND `database_error`
/// was in the transient list, so SQL syntax errors retried forever
/// until max_retries was hit. That wastes fuel and worker capacity on
/// a deterministically-broken query.
pub fn classify_error(error_msg: &str) -> String {
    // MCP-1135 (2026-05-16): cap input length at 4 KiB before
    // `to_lowercase()` + the 15-substring `.contains()` chain. The
    // classifier looks for short tokens like "504", "timed out",
    // "connection refused" — every meaningful match fits comfortably
    // in the first 4 KiB of any realistic error string. Worker-side
    // errors can include up to ~10 MiB of HTTP response body
    // previews / DLP-scrubbed LLM provider error bodies / sqlx
    // error chains, and `to_lowercase()` allocates a full-input copy
    // before every `.contains()` then walks all 16-ish patterns
    // against the full lowercased buffer. For a 10 MiB input that's
    // ~160 MiB of byte comparisons + a 10 MiB allocation per
    // classification — multiplied by retry attempts (typically 3-5)
    // per failing job. The 4 KiB cap keeps classification O(1) in
    // worst-case input size; truncation at a char boundary so
    // multi-byte UTF-8 errors don't panic.
    //
    // Same defense-in-depth class as MCP-1010 (validate_email
    // length cap before regex pass) and MCP-478 (UA truncation
    // before DLP redact). The pattern is: any function that does
    // O(N) work over a caller-controlled string needs a sane
    // upstream cap or its own internal cap.
    const MAX_CLASSIFY_INPUT_BYTES: usize = 4096;
    let truncated: &str = if error_msg.len() <= MAX_CLASSIFY_INPUT_BYTES {
        error_msg
    } else {
        // Walk back from the byte cap to the nearest UTF-8 char
        // boundary so the slice is valid Rust str.
        let mut end = MAX_CLASSIFY_INPUT_BYTES;
        while end > 0 && !error_msg.is_char_boundary(end) {
            end -= 1;
        }
        &error_msg[..end]
    };
    let lower = truncated.to_lowercase();

    // Per-host circuit breaker fast-fail (worker `circuit_open_error`).
    // Hoisted ABOVE every other bucket because the worker may append the
    // last underlying error (which can carry transient tokens like
    // "connection refused") — but a circuit-open fast-fail is
    // deliberately NON-transient: the host is known-down and cooling
    // down, so re-dispatching just hammers it. Keying on the stable
    // "circuit open" marker makes the controller-side dispatcher skip its
    // re-dispatch retries, the cross-process complement of the worker's
    // in-process retry gate.
    if lower.contains("circuit open") || lower.contains("circuit breaker open") {
        return "circuit_open".to_string();
    }

    if lower.contains("fuel exhausted") || lower.contains("out of fuel") {
        return "fuel_exhaustion".to_string();
    }
    // MCP-489: Postgres lock-timeout error message
    // `canceling statement due to lock timeout` contains the substring
    // "timeout", so it would fall into the generic `timeout` bucket
    // below before reaching the database_transient branch — losing the
    // more-precise DB classification. The four database_transient
    // phrases here are all Postgres-specific so hoisting them above
    // the generic timeout check is safe. Outcome is still "retry"
    // either way (both buckets are transient), but operator-facing
    // failure reports and per-error-class statistics need the precise
    // tag.
    if lower.contains("deadlock detected")
        || lower.contains("could not serialize access")
        || lower.contains("lock not available")
        || lower.contains("canceling statement due to lock timeout")
    {
        return "database_transient".to_string();
    }
    // MCP-546: broaden the network_transient bucket to include more
    // common transient failures that previously fell to `unknown` and
    // never retried. The retry policy uses `is_transient_error_type`,
    // so a misclassified transient error means the workflow gives up
    // on the first attempt. Real production traces show:
    //
    // * DNS-resolution failures ("no such host" / "name or service
    //   not known" / "dns lookup failed") — common during kube-dns
    //   blips, container-network startup races, or NodeLocal DNS
    //   cache restarts. Almost always recover within a retry window.
    // * TLS handshake errors ("tls handshake" / "ssl handshake") —
    //   transient races between connection-pool reuse and remote-end
    //   socket teardown.
    // * `504 Gateway Timeout` — unambiguously transient at the LB /
    //   reverse-proxy layer. Previously needed "timeout" to be in
    //   the body, which most upstream APIs include but some return
    //   bare `HTTP 504` with no text.
    // * Connection-pool exhaustion ("pool timed out" / "pool exhausted"
    //   / "no available connection") — caller retries after pool
    //   refills; same recovery model as deadlock/serialization.
    // * "broken pipe" / "connection aborted" / "EOF" — half-closed
    //   TCP connections, common when a load balancer rotates its
    //   backend pool mid-stream.
    //
    // Hoisted ABOVE the generic `timeout` branch because
    // `pool timed out` contains "timed out" — same precedence shape
    // as the MCP-489 database_transient hoist. The more-specific
    // bucket wins for downstream telemetry (operators alert on
    // `network_transient` vs generic `timeout` differently).
    if lower.contains("connection refused")
        || lower.contains("connection reset")
        || lower.contains("connection aborted")
        || lower.contains("broken pipe")
        || lower.contains("unexpected eof")
        || lower.contains("503")
        || lower.contains("502")
        || lower.contains("504")
        || lower.contains("no such host")
        || lower.contains("name or service not known")
        || lower.contains("dns lookup failed")
        || lower.contains("tls handshake")
        || lower.contains("ssl handshake")
        || lower.contains("pool timed out")
        || lower.contains("pool exhausted")
        || lower.contains("no available connection")
    {
        return "network_transient".to_string();
    }
    if lower.contains("timed out") || lower.contains("timeout") {
        return "timeout".to_string();
    }
    if lower.contains("rate limit") || lower.contains("429") || lower.contains("too many requests")
    {
        return "rate_limit".to_string();
    }
    if lower.contains("unauthorized") || lower.contains("forbidden") || lower.contains("401") {
        return "auth_failure".to_string();
    }
    if lower.contains("not found") || lower.contains("404") {
        return "not_found".to_string();
    }
    if lower.contains("wasm trap") || lower.contains("panic") {
        return "wasm_trap".to_string();
    }
    if lower.contains("memory") || lower.contains("oom") {
        return "memory_exhaustion".to_string();
    }
    if lower.contains("secret") || lower.contains("vault") {
        return "missing_secret".to_string();
    }
    if lower.contains("sql") || lower.contains("query") || lower.contains("database") {
        return "database_error".to_string();
    }
    if lower.contains("signature") || lower.contains("hmac") {
        return "signature_failure".to_string();
    }

    "unknown".to_string()
}

/// Determine if an error type is typically transient (worth retrying).
///
/// MCP-444: `database_error` removed from the transient list; the
/// classifier now emits `database_transient` for true transient DB
/// conditions, leaving `database_error` as deterministic failures that
/// should fail fast.
pub fn is_transient_error_type(error_type: &str) -> bool {
    matches!(
        error_type,
        "rate_limit" | "network_transient" | "timeout" | "database_transient"
    )
}

/// Diagnose failures for a workflow using historical execution data.
pub async fn diagnose_failures(
    pool: &PgPool,
    workflow_id: Uuid,
    hours: i64,
) -> Result<FailureDiagnosis> {
    // MCP-489: pair the zero-fallback with a warn log so a query
    // failure (column rename, schema mismatch, FK violation) is
    // observable. Without it, the caller sees a `FailureDiagnosis`
    // with 0 executions and the misleading "no executions" recommendation
    // rather than an error — exactly the lint-check-8 pattern the
    // platform learned from `get_schedule_health` zeroing.
    let (total, failed): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE status = 'failed') \
         FROM workflow_executions \
         WHERE workflow_id = $1 AND started_at > NOW() - make_interval(hours => $2::int)",
    )
    .bind(workflow_id)
    .bind(hours)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(
            %workflow_id,
            hours,
            error = %e,
            "diagnose_failures totals query failed — returning zeros"
        );
        (0, 0)
    });

    let failure_rate = if total > 0 {
        (failed as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let node_failures: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT COALESCE(node_label, node_id::text), COUNT(*), \
         COUNT(*) FILTER (WHERE status = 'failed') \
         FROM module_executions \
         WHERE workflow_execution_id IN \
           (SELECT id FROM workflow_executions WHERE workflow_id = $1 \
            AND started_at > NOW() - make_interval(hours => $2::int)) \
         GROUP BY COALESCE(node_label, node_id::text) \
         ORDER BY COUNT(*) FILTER (WHERE status = 'failed') DESC",
    )
    .bind(workflow_id)
    .bind(hours)
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(
            %workflow_id,
            hours,
            error = %e,
            "diagnose_failures per-node query failed — returning empty breakdown"
        );
        Vec::new()
    });

    let mut per_node = Vec::new();
    let mut recommendations = Vec::new();

    for (label, runs, fails) in node_failures {
        let rate = if runs > 0 {
            (fails as f64 / runs as f64) * 100.0
        } else {
            0.0
        };

        if rate > 50.0 {
            recommendations.push(format!(
                "Node '{}' has {:.0}% failure rate — investigate root cause before adding retries",
                label, rate
            ));
        } else if rate > 20.0 {
            recommendations.push(format!(
                "Node '{}' has {:.0}% failure rate — consider adding retry with exponential backoff",
                label, rate
            ));
        }

        per_node.push(NodeFailureBreakdown {
            node_label: label,
            total_runs: runs,
            failures: fails,
            failure_rate_pct: rate,
            top_error_types: vec![], // Would require joining error messages
        });
    }

    if failure_rate > 50.0 {
        recommendations.insert(
            0,
            "CRITICAL: Workflow failure rate exceeds 50% — systematic issue likely".to_string(),
        );
    }

    if total == 0 {
        recommendations
            .push("No executions in the specified period — run the workflow first".to_string());
    }

    Ok(FailureDiagnosis {
        workflow_id,
        period_hours: hours,
        total_executions: total,
        failed_executions: failed,
        failure_rate_pct: failure_rate,
        per_node_breakdown: per_node,
        recommendations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_classification() {
        assert_eq!(
            classify_error("WASM fuel exhausted after 10000000"),
            "fuel_exhaustion"
        );
        assert_eq!(classify_error("Job execution timed out"), "timeout");
        assert_eq!(classify_error("HTTP 429 Too Many Requests"), "rate_limit");
        assert_eq!(classify_error("connection refused"), "network_transient");
        assert_eq!(classify_error("401 Unauthorized"), "auth_failure");
        assert_eq!(classify_error("something random"), "unknown");
    }

    #[test]
    fn transient_classification() {
        assert!(is_transient_error_type("rate_limit"));
        assert!(is_transient_error_type("network_transient"));
        assert!(is_transient_error_type("timeout"));
        // MCP-444: database_transient is the new transient DB class.
        assert!(is_transient_error_type("database_transient"));
        assert!(!is_transient_error_type("auth_failure"));
        assert!(!is_transient_error_type("fuel_exhaustion"));
        assert!(!is_transient_error_type("wasm_trap"));
        // MCP-444: generic database_error MUST NOT be transient —
        // a SQL syntax error or constraint violation will never
        // succeed on retry.
        assert!(!is_transient_error_type("database_error"));
        // Circuit-open fast-fail is deliberately NON-transient: the host
        // is known-down and cooling down, so retrying just hammers it.
        assert!(!is_transient_error_type("circuit_open"));
    }

    #[test]
    fn circuit_open_classified_non_transient() {
        // The worker's `circuit_open_error` message shape.
        let classified = classify_error(
            "circuit open for host gmail.googleapis.com: cooling down after \
             repeated failures — skipping retries until the host recovers",
        );
        assert_eq!(classified, "circuit_open");
        assert!(
            !is_transient_error_type(&classified),
            "a circuit-open fast-fail must not trigger dispatcher retries"
        );
    }

    #[test]
    fn circuit_open_wins_over_embedded_transient_token() {
        // Even if a circuit-open message embeds the underlying transient
        // error (e.g. "connection refused"), the hoisted circuit_open
        // bucket must win so the fast-fail is not re-classified transient.
        let classified = classify_error(
            "circuit open for host api.example.com (last error: connection refused)",
        );
        assert_eq!(classified, "circuit_open");
        assert!(!is_transient_error_type(&classified));
    }

    #[test]
    fn deadlock_classified_as_database_transient() {
        // MCP-444: deadlocks are the canonical transient DB failure.
        // Even though the error message contains "database", it must
        // hit the more-specific database_transient branch first so it
        // is retried.
        let classified = classify_error(
            "Database(PgDatabaseError { severity: ERROR, code: \"40P01\", \
             message: \"deadlock detected\" })",
        );
        assert_eq!(classified, "database_transient");
        assert!(is_transient_error_type(&classified));
    }

    #[test]
    fn serialization_failure_classified_as_database_transient() {
        // Postgres serialization failures under SERIALIZABLE isolation
        // are recoverable by retrying the whole transaction.
        let classified =
            classify_error("ERROR: could not serialize access due to concurrent update");
        assert_eq!(classified, "database_transient");
        assert!(is_transient_error_type(&classified));
    }

    #[test]
    fn sql_syntax_error_is_not_transient() {
        // MCP-444: pre-fix the substring `sql` was enough to flip this
        // into the transient bucket and retry until max_retries —
        // wasting fuel on a deterministic failure. The sqlx-wrapped
        // form below contains both `Database(` and the inner `syntax
        // error` body.
        let classified = classify_error(
            "Database(PgDatabaseError { code: \"42601\", message: \"syntax error at or near \\\"SELECT\\\"\" })",
        );
        assert_eq!(classified, "database_error");
        assert!(!is_transient_error_type(&classified));
    }

    #[test]
    fn lock_timeout_classified_as_database_transient_not_timeout() {
        // MCP-489: pre-fix, the substring "timeout" in
        // `canceling statement due to lock timeout` was caught by the
        // generic timeout branch BEFORE the database_transient branch
        // ran, so this Postgres-specific lock-timeout was tagged
        // `timeout` instead of `database_transient`. Both are
        // transient (retry happens either way), but per-error-class
        // operator reports lose the DB precision. Hoisting the
        // DB-transient check above timeout fixes the precedence.
        let classified = classify_error("ERROR: canceling statement due to lock timeout");
        assert_eq!(classified, "database_transient");
        assert!(is_transient_error_type(&classified));
    }

    #[test]
    fn constraint_violation_is_not_transient() {
        // sqlx wraps constraint violations as Database(PgDatabaseError ...)
        // so the substring "database" hits the generic database_error
        // branch — which is NOT in the transient list post-MCP-444.
        let classified = classify_error(
            "Database(PgDatabaseError { code: \"23505\", message: \"duplicate key value violates unique constraint\" })",
        );
        assert_eq!(classified, "database_error");
        assert!(!is_transient_error_type(&classified));
    }

    /// MCP-546: DNS-resolution failures must classify as transient
    /// so they retry through a momentary kube-dns / NodeLocal DNS
    /// blip. Pre-fix they fell to `unknown` and never retried.
    #[test]
    fn dns_resolution_failures_are_network_transient() {
        for msg in [
            "Failed to fetch: no such host (api.example.com)",
            "tonic transport: Error { Status { source: Some(\"name or service not known\") } }",
            "reqwest::Error: dns lookup failed for 'svc.cluster.local'",
        ] {
            let c = classify_error(msg);
            assert_eq!(c, "network_transient", "got {c:?} for msg {msg:?}");
            assert!(is_transient_error_type(&c));
        }
    }

    /// MCP-546: TLS handshake hiccups (often racy with connection-pool
    /// reuse) must retry.
    #[test]
    fn tls_handshake_failures_are_network_transient() {
        for msg in [
            "tls handshake eof",
            "SSL handshake failed: peer closed connection without sending complete message body",
        ] {
            let c = classify_error(msg);
            assert_eq!(c, "network_transient", "got {c:?} for msg {msg:?}");
            assert!(is_transient_error_type(&c));
        }
    }

    /// MCP-546: HTTP 504 Gateway Timeout is unambiguously transient
    /// at the LB / reverse-proxy layer. Pre-fix it depended on the
    /// upstream body including "timeout"; bare `HTTP 504` strings
    /// (common from minimal LBs) fell to `unknown`.
    #[test]
    fn http_504_is_network_transient() {
        let c = classify_error("upstream returned HTTP 504");
        assert_eq!(c, "network_transient");
        assert!(is_transient_error_type(&c));
    }

    /// MCP-546: connection-pool exhaustion = caller retries after the
    /// pool refills. Same recovery model as deadlock.
    #[test]
    fn pool_exhaustion_is_network_transient() {
        for msg in [
            "pool timed out while waiting for an open connection",
            "deadpool: pool exhausted",
            "no available connection in the pool after 5s",
        ] {
            let c = classify_error(msg);
            assert_eq!(c, "network_transient", "got {c:?} for msg {msg:?}");
            assert!(is_transient_error_type(&c));
        }
    }

    /// MCP-546: half-closed TCP connections (broken pipe / aborted /
    /// EOF) are usually a load-balancer rotating its backend pool
    /// mid-stream. Retry succeeds against the new backend.
    #[test]
    fn half_closed_tcp_is_network_transient() {
        for msg in [
            "io error: broken pipe",
            "connection aborted",
            "unexpected EOF during chunked decode",
        ] {
            let c = classify_error(msg);
            assert_eq!(c, "network_transient", "got {c:?} for msg {msg:?}");
            assert!(is_transient_error_type(&c));
        }
    }

    /// MCP-546: tripwire that the broadened bucket doesn't accidentally
    /// catch unambiguously-permanent errors. "no such file" contains
    /// "no such" but NOT "no such host" — must stay in the unknown /
    /// downstream bucket, not flip to network_transient.
    #[test]
    fn no_such_host_is_specific_does_not_match_no_such_file() {
        // The closer match path for this is `not_found` ("not found"
        // earlier in the chain) — but a fresh `no such file` doesn't
        // hit any earlier branch and would have flipped to
        // network_transient if we accidentally matched just "no such".
        let c = classify_error("io error: no such file or directory");
        assert_ne!(c, "network_transient");
    }

    /// MCP-1135: oversize input is truncated to 4 KiB before
    /// classification. Verify (a) classification works when the
    /// matching pattern lives in the first 4 KiB, and (b) classify
    /// completes quickly even on a multi-MiB input.
    #[test]
    fn classify_handles_oversize_input_with_match_in_prefix() {
        // Put the classifying token in the first ~1 KiB then pad
        // with megabytes of irrelevant filler. The match should still
        // fire — the cap only drops bytes AFTER 4 KiB, and the
        // pattern is well within that.
        let mut huge = String::from("HTTP 504 from upstream — ");
        huge.push_str(&"a".repeat(5 * 1024 * 1024)); // 5 MiB filler
        let c = classify_error(&huge);
        assert_eq!(c, "network_transient");
        assert!(is_transient_error_type(&c));
    }

    #[test]
    fn classify_handles_match_beyond_cap_as_unknown() {
        // Match token lives BEYOND the 4 KiB cap → classifier treats
        // the input as if the match weren't there. This is the
        // intentional trade-off: classification is bounded; if your
        // error message buries the meaningful token past 4 KiB,
        // your error formatter has a bigger problem.
        let mut huge = String::from(&"x".repeat(8000));
        huge.push_str(" HTTP 504");
        let c = classify_error(&huge);
        assert_eq!(c, "unknown");
    }

    #[test]
    fn classify_truncates_at_utf8_char_boundary() {
        // Multi-byte UTF-8 char that straddles the 4 KiB boundary
        // must not cause a panic. Construct an input where byte 4094
        // starts a 3-byte UTF-8 sequence — the truncator must walk
        // back to a valid boundary.
        let mut s = String::with_capacity(4096);
        // Pad to byte 4094.
        s.push_str(&"a".repeat(4094));
        // Push a 3-byte char (€ = U+20AC = 0xE2 0x82 0xAC) at bytes
        // 4094-4096. Byte 4096 is mid-char.
        s.push('€');
        // Even more filler beyond the cap.
        s.push_str(&"b".repeat(1000));
        // Must not panic.
        let _ = classify_error(&s);
    }
}
