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
/// The EGRESS-surface POLICY and CAP classes the worker stamps.
///
/// Originally the classes for `wit_http`'s two non-`networkerror`
/// discriminants; it now spans all four egress surfaces. Three of them
/// (`graphql`, `webhook`, `http_stream`) have WIT enums with NO deny variant
/// at all, so their denials ride the same discriminant as their transport
/// failures and the marker is the only thing that tells them apart. The worker
/// guarantees the marker describes the call that produced the message — see
/// `talos_worker_runtime::reason_class`'s "totality, not clearing" section.
///
/// Hand-mirrored from `talos_worker_runtime::reason_class::HTTP_POLICY_CLASSES`
/// — this crate deliberately does not depend on the worker runtime (it would
/// pull wasmtime into the controller's retry path), so the pinning is by test:
/// that module's `closed_set_snapshot` fails if a token is added or renamed
/// without updating this list.
///
/// Every member is DETERMINISTIC — a policy re-runs identically, a cap
/// re-trips identically — so every member maps to `capability_denied`, which
/// `is_transient_error_type` does not treat as retryable. `url-parse` is the
/// one exception and is handled separately below: an unparseable URL is an
/// AUTHORING error, not a denial, and calling it `capability_denied` would
/// send the operator hunting a policy that never fired.
const HTTP_POLICY_DENIAL_CLASSES: &[&str] = &[
    "url-too-long",
    "insecure-scheme",
    "capability-world",
    "no-allowlist",
    "private-ip",
    "allowed-hosts",
    "tier1-llm-egress",
    "tier1-public-ip-egress",
    "write-ceiling",
    "write-ceiling-strict-egress",
    "method-allowlist",
    "execution-rate-limit",
    "per-host-rate-limit",
    "request-header-cap",
    "request-body-cap",
    "graphql-introspection",
    "sse-stream-cap",
];

/// Extract the `[reason_class=<token>]` token the worker stamped, if any.
///
/// Parsed ONCE rather than adding sixteen more `.contains()` scans to a
/// function whose own doc-comment caps its input at 4 KiB precisely because
/// the substring chain is the cost. Returns the token only — the caller
/// decides the bucket.
///
/// `lower` must already be lowercased and truncated by the caller.
fn reason_class_token(lower: &str) -> Option<&str> {
    const KEY: &str = "reason_class=";
    let start = lower.find(KEY)? + KEY.len();
    let rest = &lower[start..];
    let end = rest.find(']').unwrap_or(rest.len());
    let tok = &rest[..end];
    if tok.is_empty() {
        None
    } else {
        Some(tok)
    }
}

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
    if lower.contains("circuit open")
        || lower.contains("circuit breaker open")
        || lower.contains("reason_class=circuit-open")
    {
        return "circuit_open".to_string();
    }

    // ── Host-side WIT deny / cap classes ─────────────────────────────────
    //
    // The worker's `wit_http` error enum is a payload-less C-style
    // discriminant, so a Tier-1 data-egress deny, an execution cancellation
    // and a response-size refusal all reach the controller as the same bare
    // `networkerror` token that the `network_transient` bucket below now
    // matches. Each of these is DETERMINISTIC — the actor's egress ceiling,
    // the cancellation, and the oversized response are identical on the next
    // attempt — so they must be carved out BEFORE the generic token, exactly
    // like the circuit-open hoist above.
    //
    // `[reason_class=…]` is stamped by the worker at the emitting host site
    // (`talos_worker_runtime::reason_class`); `forbiddenhost` is the other
    // WIT deny variant (host allowlist / method allowlist / request caps).
    if lower.contains("reason_class=tier1-egress")
        || lower.contains("forbiddenhost")
        || lower.contains("reason_class=header-cap")
        || lower.contains("reason_class=response-too-large")
    {
        return "capability_denied".to_string();
    }
    if lower.contains("reason_class=cancelled") {
        return "cancelled".to_string();
    }
    // A missing / ungranted vault slot is a configuration error, not a
    // network blip — even though the host had to report it as `networkerror`.
    // Hoisted above the `missing_secret` bucket's own position for the same
    // precedence reason as the classes above.
    if lower.contains("reason_class=secret-lookup") {
        return "missing_secret".to_string();
    }
    // The `invalidurl` and `forbiddenhost` half of the same collapse.
    //
    // `forbiddenhost` was already caught above, but only as ONE bucket for at
    // least ten different policies whose remediations are unrelated — the
    // marker is what tells `allowed-hosts` (extend the allowlist) from
    // `capability-world` (recompile with an http world) from `write-ceiling`
    // (the actor is read-only). `invalidurl` matched NOTHING here at all, so a
    // plaintext-scheme SECURITY refusal — the gate that stops a `vault://`
    // header going out in the clear — was filed under `unknown` and rendered
    // to the operator as an indistinguishable typo.
    //
    // Placed with its siblings above rather than lower down because a
    // HOST-stamped marker is authoritative and module prose is not; the same
    // reason `circuit-open` and `tier1-egress` are hoisted. Nothing existing
    // moves: every token below is newly minted, so no message that predates
    // this change can carry one.
    if let Some(tok) = reason_class_token(&lower) {
        if HTTP_POLICY_DENIAL_CLASSES.contains(&tok) {
            return "capability_denied".to_string();
        }
        // An author typo, deterministic like the denials but with a different
        // fix. Its own bucket rather than `unknown` (where it landed before)
        // so the failure reports can say which of the three `invalidurl`
        // causes fired. NOT in `is_transient_error_type`, so the retry
        // behaviour is byte-identical to the `unknown` it replaces.
        if tok == "url-parse" {
            return "invalid_url".to_string();
        }
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
        // 2026-07-30: the bare WIT transport token. A read-only Gmail GET
        // module is correctly granted 2 transient retries by
        // `default_max_retries_for_module`, but the dispatcher's classifier
        // gate vetoed them because the literal failure string —
        // `Component returned error: list fetch: Error { code: 2, name:
        // "networkerror", message: "" }` — matched NOTHING here, classified
        // `unknown`, and the job ran exactly once (13-15 failures/hour across
        // four workflows on 2026-07-23). Transient BY DEFAULT even though the
        // enum spans non-transient causes: those are carved out above by their
        // `reason_class`, and when the cause is genuinely unknown the
        // read-only default (retry a possible blip) is the safer error. The
        // per-host circuit breaker backstops a genuinely-down host.
        || lower.contains("networkerror")
        // The precise transport classes the worker now stamps. Listed
        // explicitly rather than relying on the bare token above so that
        // dropping the `networkerror` arm alone cannot silently un-retry them.
        || lower.contains("reason_class=dns")
        || lower.contains("reason_class=tls")
        || lower.contains("reason_class=connect-refused")
        || lower.contains("reason_class=connect-failed")
        || lower.contains("reason_class=send-failed")
        || lower.contains("reason_class=response-stream")
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

    // DEAD AND BROKEN — read this before "fixing" it (audited 2026-07-30).
    //
    // `module_executions` has NO `node_label` and NO `node_id` column (it
    // carries `module_id` + `workflow_execution_id` and nothing node-shaped),
    // so this statement fails to prepare on EVERY call. The `unwrap_or_else`
    // below turns that into an empty breakdown plus a warn, and
    // `diagnose_failures` has zero callers workspace-wide — which is the only
    // reason nobody has noticed.
    //
    // THE TRAP: adding a `node_label` column would make this compile and start
    // reporting — with the wrong denominator. `module_executions` holds one row
    // per DISPATCH, not one per workflow run, and as of 2026-07-30 that
    // includes one row per loop-body ITERATION (a `loop` node is capped at 100
    // iterations, so a single workflow execution can contribute up to 100 rows
    // for one node). `COUNT(*)` here is therefore "dispatches", never "runs",
    // and rendering it as the latter beside `total`/`failed` — which ARE
    // per-workflow-execution, counted off `workflow_executions` above — would
    // put two different populations in one report under one label. If this is
    // ever revived: label the column `dispatches`, or aggregate
    // `COUNT(DISTINCT workflow_execution_id)` instead, and say which you chose.
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
        // Both wordings: the pre-2026-08 "exhausted after N" form (still
        // present in historical rows) and the current
        // `fuel_exhausted_message` form, which has no "after". Retyped rather
        // than bound to the producer — this crate deliberately carries no
        // dependency on `talos-worker-runtime`.
        assert_eq!(
            classify_error("WASM fuel exhausted after 10000000"),
            "fuel_exhaustion"
        );
        assert_eq!(
            classify_error(
                "WASM fuel exhausted: the module consumed 10000000 instructions of a \
                 10000000-instruction budget and did not finish"
            ),
            "fuel_exhaustion"
        );
        assert_eq!(classify_error("Job execution timed out"), "timeout");
        assert_eq!(classify_error("HTTP 429 Too Many Requests"), "rate_limit");
        assert_eq!(classify_error("connection refused"), "network_transient");
        assert_eq!(classify_error("401 Unauthorized"), "auth_failure");
        assert_eq!(classify_error("something random"), "unknown");
        // A bare `invalidurl` with no marker keeps its pre-change bucket: the
        // new arm is gated on a marker, not on the discriminant.
        assert_eq!(
            classify_error(
                r#"Component returned error: HTTP request failed: Error { code: 0, name: "invalidurl", message: "" }"#
            ),
            "unknown"
        );
        // A marker whose token is not in the closed set falls through
        // untouched rather than defaulting into a denial bucket.
        assert_eq!(
            classify_error("something random [reason_class=not-a-real-token]"),
            "unknown"
        );
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

    /// The controller half of the cancellation receiver contract, asserted in
    /// BOTH directions.
    ///
    /// A cancelled egress guard reaches this classifier as the bare WIT
    /// `networkerror` token PLUS the host-stamped `[reason_class=cancelled]`
    /// marker. Without the marker the string lands in the `network_transient`
    /// bucket, the dispatcher re-dispatches, and the retry runs on a FRESH
    /// worker context whose `cancelled` flag is false — i.e. the operator's
    /// cancel silently does not stick. `http::fetch_all` and `graphql::execute`
    /// were emitting exactly the unmarked form until the worker-side parity fix.
    #[test]
    fn a_cancelled_egress_is_non_transient_only_because_of_the_marker() {
        const GUEST: &str = "Component returned error: list fetch: Error { code: 2, \
name: \"networkerror\", message: \"\" }";

        let marked = format!("{GUEST} [reason_class=cancelled]");
        assert_eq!(classify_error(&marked), "cancelled");
        assert!(
            !is_transient_error_type("cancelled"),
            "a cancelled execution must never be re-dispatched"
        );

        // FALSIFICATION DIRECTION. If this ever stops being transient the test
        // above proves nothing, because the marker would no longer be what
        // makes the difference.
        assert_eq!(
            classify_error(GUEST),
            "network_transient",
            "the unmarked form is the pre-fix behaviour and must stay transient \
             for the marked assertion above to be meaningful"
        );
        assert!(is_transient_error_type("network_transient"));
    }

    /// The marker must beat the `networkerror` token regardless of ordering
    /// inside the message — the two are matched by different `if` blocks and
    /// only the HOIST keeps `cancelled` winning.
    #[test]
    fn the_cancelled_arm_outranks_the_networkerror_arm() {
        assert_eq!(
            classify_error("[reason_class=cancelled] networkerror"),
            "cancelled"
        );
        assert_eq!(
            classify_error("networkerror [reason_class=cancelled]"),
            "cancelled"
        );
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

    /// The 2026-07-30 buried lede. `default_max_retries_for_module` correctly
    /// grants a read-only Gmail GET module 2 transient retries, but the
    /// dispatcher's classifier gate vetoed them: the literal failure string
    /// matched NO token here, classified `unknown`, and the job ran exactly
    /// ONCE. 13-15 failures/hour across four workflows on 2026-07-23.
    #[test]
    fn bare_networkerror_is_network_transient() {
        let live = r#"Component returned error: list fetch: Error { code: 2, name: "networkerror", message: "" }"#;
        let c = classify_error(live);
        assert_eq!(c, "network_transient");
        assert!(
            is_transient_error_type(&c),
            "the granted retry budget must not be vetoed"
        );
        // Mutation guard: no other token in this string can carry the result.
        assert_eq!(classify_error("networkerror"), "network_transient");
    }

    /// The other WIT deny variant. `forbiddenhost` is a capability denial —
    /// host allowlist, method allowlist, or a request cap — and is
    /// deterministic. It must classify NON-transient, and it must do so
    /// BEFORE the broadened network bucket can see the `networkerror` token
    /// that a mixed message may also carry.
    #[test]
    fn forbiddenhost_is_non_transient() {
        let c = classify_error(
            r#"Component returned error: fetch: Error { code: 3, name: "forbiddenhost", message: "" }"#,
        );
        assert_eq!(c, "capability_denied");
        assert!(!is_transient_error_type(&c));
    }

    /// Circuit-open reaches the controller as a bare `networkerror` (the WIT
    /// enum is payload-less), so broadening the bucket would have started
    /// retrying against a host the breaker already declared down. The
    /// `reason_class` marker plus the hoisted bucket is what prevents it.
    #[test]
    fn circuit_open_reason_class_beats_the_networkerror_token() {
        let msg = r#"Component returned error: fetch: Error { code: 2, name: "networkerror", message: "" } [reason_class=circuit-open]"#;
        assert!(msg.contains("networkerror"), "test premise");
        let c = classify_error(msg);
        assert_eq!(c, "circuit_open");
        assert!(!is_transient_error_type(&c));
    }

    /// Every `reason_class` token the worker can stamp, and the class each
    /// must land in. The token list is hand-mirrored from
    /// `talos_worker_runtime::reason_class::ALL` (this crate must not depend
    /// on the worker runtime); that module's `closed_set_snapshot` test fails
    /// if a token is added or renamed without updating this table.
    #[test]
    fn every_reason_class_token_maps_to_the_right_bucket() {
        let cases: &[(&str, &str, bool)] = &[
            // token, expected class, expected transient
            ("dns", "network_transient", true),
            ("tls", "network_transient", true),
            ("connect-refused", "network_transient", true),
            ("connect-failed", "network_transient", true),
            ("send-failed", "network_transient", true),
            ("response-stream", "network_transient", true),
            ("circuit-open", "circuit_open", false),
            ("tier1-egress", "capability_denied", false),
            ("cancelled", "cancelled", false),
            ("response-too-large", "capability_denied", false),
            ("header-cap", "capability_denied", false),
            ("secret-lookup", "missing_secret", false),
            ("timeout", "timeout", true),
        ];
        for (token, expected, transient) in cases {
            // `timeout` is the one token paired with `wit_http::Error::Timeout`
            // rather than `networkerror`, so the guest renders a different
            // enum name. Building the realistic pairing keeps the case honest
            // (an artificial `networkerror` + `reason_class=timeout` message
            // would classify network_transient — same transience, wrong class).
            let wit_name = if *token == "timeout" {
                "timeout"
            } else {
                "networkerror"
            };
            let msg = format!(
                r#"Component returned error: fetch: Error {{ code: 2, name: "{wit_name}", message: "" }} [reason_class={token}]"#
            );
            let c = classify_error(&msg);
            assert_eq!(&c, expected, "token {token:?} classified {c:?}");
            assert_eq!(
                is_transient_error_type(&c),
                *transient,
                "token {token:?} transience"
            );
        }
    }

    /// The `invalidurl` / `forbiddenhost` half of the closed set, in the
    /// realistic pairing — each token stamped onto the discriminant the
    /// emitting site actually returns, because the worker will never stamp it
    /// onto any other (`last_network_reason_suffix`).
    ///
    /// Hand-mirrored from `talos_worker_runtime::reason_class`, same as the
    /// table above; `closed_set_snapshot` over there fails if a token is added
    /// or renamed without this list moving with it.
    #[test]
    fn every_http_policy_token_maps_to_the_right_bucket() {
        // (token, wit discriminant, expected class)
        let cases: &[(&str, &str, &str)] = &[
            ("capability-world", "forbiddenhost", "capability_denied"),
            ("no-allowlist", "forbiddenhost", "capability_denied"),
            ("private-ip", "forbiddenhost", "capability_denied"),
            ("allowed-hosts", "forbiddenhost", "capability_denied"),
            ("tier1-llm-egress", "forbiddenhost", "capability_denied"),
            (
                "tier1-public-ip-egress",
                "forbiddenhost",
                "capability_denied",
            ),
            ("write-ceiling", "forbiddenhost", "capability_denied"),
            (
                "write-ceiling-strict-egress",
                "forbiddenhost",
                "capability_denied",
            ),
            ("method-allowlist", "forbiddenhost", "capability_denied"),
            ("execution-rate-limit", "forbiddenhost", "capability_denied"),
            ("per-host-rate-limit", "forbiddenhost", "capability_denied"),
            ("request-header-cap", "forbiddenhost", "capability_denied"),
            ("request-body-cap", "forbiddenhost", "capability_denied"),
            ("url-too-long", "invalidurl", "capability_denied"),
            ("insecure-scheme", "invalidurl", "capability_denied"),
            // The one AUTHORING error among them. Its own bucket, so a report
            // does not tell an operator a policy fired when none did.
            ("url-parse", "invalidurl", "invalid_url"),
        ];
        for (token, wit, expected) in cases {
            let msg = format!(
                r#"Component returned error: fetch: Error {{ name: "{wit}", message: "" }} [reason_class={token}]"#
            );
            let c = classify_error(&msg);
            assert_eq!(&c, expected, "token {token:?} classified {c:?}");
            assert!(
                !is_transient_error_type(&c),
                "token {token:?} is a deterministic policy/cap/authoring failure \\
                 and MUST NOT be retried — it landed in the transient class {c:?}"
            );
        }
    }

    /// THE SAFETY PROPERTY, stated as the thing that must not happen rather
    /// than as a list of things that do.
    ///
    /// Adding a marker adds TEXT, and this classifier is a substring chain, so
    /// a badly chosen token could drag a message into an EARLIER bucket. The
    /// direction that matters is non-transient → transient: that burns retry
    /// budget on a deterministic failure, the 2026-07-23 outage class.
    ///
    /// Asserted for every new token against every WIT discriminant it could
    /// conceivably ride on — including the pairings the worker will not
    /// actually produce, so the property survives a future site that pairs
    /// differently.
    #[test]
    fn no_new_token_can_make_any_message_transient() {
        let mut all: Vec<&str> = HTTP_POLICY_DENIAL_CLASSES.to_vec();
        all.push("url-parse");
        for token in &all {
            for wit in ["invalidurl", "forbiddenhost", "networkerror", "timeout"] {
                let bare = format!(
                    r#"Component returned error: fetch: Error {{ name: "{wit}", message: "" }}"#
                );
                let marked = format!("{bare} [reason_class={token}]");
                let before = is_transient_error_type(&classify_error(&bare));
                let after = is_transient_error_type(&classify_error(&marked));
                assert!(
                    !(after && !before),
                    "[reason_class={token}] moved a {wit} message from NON-TRANSIENT \\
                     to TRANSIENT — that retries a deterministic failure"
                );
            }
        }
    }

    /// The classification of every message shape that exists TODAY is
    /// unchanged. Pinned as literals rather than derived, for the reason the
    /// wire-format snapshots exist: a behavioural test written against the new
    /// code cannot catch a change that moved both sides together.
    ///
    /// The table was produced by running THIS function and the pre-change one
    /// (`git show HEAD:…`) over a 332-case corpus — every prefix × every WIT
    /// discriminant × every pre-existing `reason_class` token, plus the
    /// non-WIT failure strings the controller sees — and comparing both the
    /// bucket and `is_transient_error_type`. Zero differences. The rows below
    /// are the representative slice; the property that makes the whole corpus
    /// safe is structural and stated in `new_tokens_cannot_appear_on_an_old_message`.
    #[test]
    fn existing_message_shapes_classify_exactly_as_before() {
        let cases: &[(&str, &str)] = &[
            (
                r#"Component returned error: fetch: Error { code: 2, name: "networkerror", message: "" }"#,
                "network_transient",
            ),
            (
                r#"Component returned error: fetch: Error { code: 3, name: "forbiddenhost", message: "" }"#,
                "capability_denied",
            ),
            (
                r#"Component returned error: fetch: Error { code: 0, name: "invalidurl", message: "" }"#,
                "unknown",
            ),
            (
                r#"Component returned error: fetch: Error { code: 1, name: "timeout", message: "" }"#,
                "timeout",
            ),
            (
                r#"Component returned error: fetch: Error { code: 2, name: "networkerror", message: "" } [reason_class=dns]"#,
                "network_transient",
            ),
            (
                r#"Component returned error: fetch: Error { code: 2, name: "networkerror", message: "" } [reason_class=circuit-open]"#,
                "circuit_open",
            ),
            (
                r#"Component returned error: fetch: Error { code: 2, name: "networkerror", message: "" } [reason_class=tier1-egress]"#,
                "capability_denied",
            ),
            (
                r#"Component returned error: fetch: Error { code: 2, name: "networkerror", message: "" } [reason_class=cancelled]"#,
                "cancelled",
            ),
            (
                r#"Component returned error: fetch: Error { code: 2, name: "networkerror", message: "" } [reason_class=secret-lookup]"#,
                "missing_secret",
            ),
            ("connection refused", "network_transient"),
            ("401 Unauthorized", "auth_failure"),
            ("HTTP 429 Too Many Requests", "rate_limit"),
            ("Job execution timed out", "timeout"),
            ("WASM fuel exhausted after 10000000", "fuel_exhaustion"),
            (
                "canceling statement due to lock timeout",
                "database_transient",
            ),
            ("something random", "unknown"),
        ];
        for (msg, expected) in cases {
            assert_eq!(&classify_error(msg), expected, "shape: {msg}");
        }
    }

    /// Why the table above is a slice and not an exhaustive corpus: no message
    /// that predates this change can carry a newly-minted token, because the
    /// tokens did not exist. The new arm therefore cannot fire on old text at
    /// all — it is not a re-ordering of the existing chain, it is a branch on
    /// a value only the new producer can emit.
    ///
    /// Pinned so that "reuse an existing-looking token" — the obvious
    /// simplification — fails here instead of silently re-routing shipped
    /// messages.
    #[test]
    fn new_tokens_cannot_appear_on_an_old_message() {
        // The tokens the producer could stamp BEFORE this change.
        const PRE_EXISTING: &[&str] = &[
            "dns",
            "tls",
            "connect-refused",
            "connect-failed",
            "send-failed",
            "circuit-open",
            "tier1-egress",
            "cancelled",
            "response-too-large",
            "header-cap",
            "response-stream",
            "timeout",
            "secret-lookup",
        ];
        let mut minted: Vec<&str> = HTTP_POLICY_DENIAL_CLASSES.to_vec();
        minted.push("url-parse");
        for m in &minted {
            assert!(
                !PRE_EXISTING.contains(m),
                "{m:?} is not newly minted — a message that predates this change \\
                 could already carry it, so the new arm CAN re-route old text \\
                 and the differential proof above no longer holds"
            );
        }
    }

    /// WHY THE WORKER GATES THE MARKER, pinned here because the hazard lives
    /// in THIS function's bucket ORDER, not in the worker.
    ///
    /// `network_transient` is checked before `auth_failure` (and before
    /// `rate_limit`), so ANY message carrying a `reason_class` transport token
    /// classifies transient regardless of what else it says. A `401` that
    /// picked up a stale `[reason_class=dns]` would therefore be retried to
    /// exhaustion — a permanent error treated as a blip.
    ///
    /// The producer side is what prevents it: the worker attaches the marker
    /// ONLY when the guest error carries the opaque `networkerror` token the
    /// class exists to explain (`last_network_reason_suffix`). This test
    /// documents the sharp edge so nobody "simplifies" that gate away, and
    /// fails loudly if the bucket order is ever changed underneath it.
    #[test]
    fn transport_marker_outranks_auth_so_the_producer_must_gate_it() {
        assert_eq!(classify_error("HTTP 401 Unauthorized"), "auth_failure");
        assert_eq!(
            classify_error("HTTP 401 Unauthorized [reason_class=dns]"),
            "network_transient",
            "bucket order makes a stray transport marker outrank auth — the \
             worker MUST NOT attach one to a non-networkerror message"
        );
    }

    /// The pre-existing suffixed forms must keep classifying exactly as
    /// before — the broadening adds a token, it must not reroute anything.
    #[test]
    fn broadening_does_not_disturb_existing_classifications() {
        assert_eq!(classify_error("connection refused"), "network_transient");
        assert_eq!(classify_error("401 Unauthorized"), "auth_failure");
        assert_eq!(classify_error("HTTP 429 Too Many Requests"), "rate_limit");
        assert_eq!(classify_error("Job execution timed out"), "timeout");
        assert_eq!(
            classify_error("WASM fuel exhausted after 10000000"),
            "fuel_exhaustion"
        );
        assert_eq!(classify_error("something random"), "unknown");
    }

    // ── The three sibling egress surfaces (#714 follow-up) ──────────────
    //
    // `wit_http` was covered first. Its three siblings — `graphql`, `webhook`,
    // `http_stream` — were then inventoried by script, and the shape of the
    // problem is different on each:
    //
    //   * graphql:     17 `networkerror` returns, 16 deterministic, 1 transport.
    //                  `networkerror` is TRANSIENT here, so every one of those
    //                  16 denials was being re-dispatched. The live bug.
    //   * webhook:     16 `sendfailed` returns, 15 deterministic, 1 transport.
    //                  `sendfailed` matches no arm at all → `unknown` →
    //                  non-transient. Diagnostic only.
    //   * http_stream: hyphenated WIT cases (`forbidden-host`), which the
    //                  `forbiddenhost` arms miss; `forbidden-host` matched
    //                  `forbidden` and read as `auth_failure`.

    /// The graphql shapes, which are the ONLY ones whose transience moves.
    ///
    /// Both directions, because a one-directional assertion passes on the
    /// broken tree too: the unmarked message must still be `network_transient`
    /// (that is the bug, and it is what the marker has to overcome) and the
    /// marked one must be `capability_denied`.
    #[test]
    fn graphql_denials_stop_being_retried_as_network_blips() {
        const BARE: &str = r#"Component returned error: gql: Error { code: 0, name: "networkerror", message: "" }"#;
        assert_eq!(
            classify_error(BARE),
            "network_transient",
            "premise: a bare graphql networkerror really was retried"
        );
        assert!(is_transient_error_type(&classify_error(BARE)));

        for token in [
            "capability-world",
            "no-allowlist",
            "private-ip",
            "allowed-hosts",
            "tier1-llm-egress",
            "tier1-public-ip-egress",
            "method-allowlist",
            "execution-rate-limit",
            "request-header-cap",
            "request-body-cap",
            "url-too-long",
            "insecure-scheme",
            "graphql-introspection",
        ] {
            let marked = format!("{BARE} [reason_class={token}]");
            let c = classify_error(&marked);
            assert_eq!(&c, "capability_denied", "token {token}");
            assert!(
                !is_transient_error_type(&c),
                "graphql denial {token} is still retryable"
            );
        }

        // The ONE transport site keeps its retry. This is the property the
        // worker's totality rule exists to preserve — a swallowed denial must
        // not veto it.
        for token in [
            "dns",
            "tls",
            "connect-refused",
            "connect-failed",
            "send-failed",
        ] {
            let marked = format!("{BARE} [reason_class={token}]");
            let c = classify_error(&marked);
            assert_eq!(&c, "network_transient", "transport token {token}");
            assert!(is_transient_error_type(&c));
        }

        // And the `queryerror` half: `queryerror` contains `query`, so a
        // read-only actor's write-ceiling refusal was reported as a DATABASE
        // error. Non-transient either way — a remediation fix.
        const Q: &str =
            r#"Component returned error: gql: Error { code: 2, name: "queryerror", message: "" }"#;
        assert_eq!(classify_error(Q), "database_error", "premise");
        assert_eq!(
            classify_error(&format!("{Q} [reason_class=write-ceiling]")),
            "capability_denied"
        );
    }

    /// `webhook` and `http_stream`: the bucket moves, the TRANSIENCE does not.
    /// Both were already non-transient in every direction, which is why these
    /// two surfaces carry no retry risk at all.
    #[test]
    fn webhook_and_stream_denials_change_bucket_but_never_transience() {
        const SENDFAILED: &str =
            r#"Component returned error: hook: Error { code: 1, name: "sendfailed", message: "" }"#;
        const FORBIDDEN: &str = r#"Component returned error: sse: Error { code: 1, name: "forbidden-host", message: "" }"#;
        // Premises: what shipped.
        assert_eq!(classify_error(SENDFAILED), "unknown");
        assert_eq!(
            classify_error(FORBIDDEN),
            "auth_failure",
            "premise: `forbidden-host` matched the substring `forbidden` and \
             sent the operator after a credential that was fine"
        );
        assert!(!is_transient_error_type("unknown"));
        assert!(!is_transient_error_type("auth_failure"));

        for (shape, token) in [
            (SENDFAILED, "allowed-hosts"),
            (SENDFAILED, "private-ip"),
            (SENDFAILED, "no-allowlist"),
            (SENDFAILED, "write-ceiling"),
            (FORBIDDEN, "capability-world"),
            (FORBIDDEN, "allowed-hosts"),
            (FORBIDDEN, "write-ceiling-strict-egress"),
            (FORBIDDEN, "per-host-rate-limit"),
        ] {
            let c = classify_error(&format!("{shape} [reason_class={token}]"));
            assert_eq!(&c, "capability_denied", "{token} on {shape}");
            assert!(!is_transient_error_type(&c));
        }
        // The stream concurrency cap, distinct from the per-host budget.
        assert_eq!(
            classify_error(r#"Error { name: "rate-limited" } [reason_class=sse-stream-cap]"#),
            "capability_denied"
        );
    }

    /// The two tokens minted by the sibling-surface change are newly minted
    /// too, so the `new_tokens_cannot_appear_on_an_old_message` argument still
    /// covers the whole set. Asserted rather than assumed: reusing an
    /// existing-looking token is the obvious simplification and it would
    /// silently re-route shipped messages.
    #[test]
    fn the_sibling_surface_tokens_are_also_newly_minted() {
        for t in ["graphql-introspection", "sse-stream-cap"] {
            assert!(HTTP_POLICY_DENIAL_CLASSES.contains(&t));
            // Not a substring of any pre-existing token, and no pre-existing
            // token is a substring of it — so no old message can carry one.
            for old in [
                "dns",
                "tls",
                "connect-refused",
                "connect-failed",
                "send-failed",
                "circuit-open",
                "tier1-egress",
                "cancelled",
                "response-too-large",
                "header-cap",
                "response-stream",
                "timeout",
                "secret-lookup",
            ] {
                assert!(!t.contains(old), "{t} contains {old}");
            }
        }
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
