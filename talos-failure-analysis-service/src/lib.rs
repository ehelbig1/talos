//! Execution failure-analysis service: loads a failed/cancelled
//! execution, gathers its `node_failed` events, classifies each failure
//! into a user-actionable bucket with matching remediation steps, and
//! optionally applies the config-field auto-fix — the orchestration that
//! previously lived inline in
//! `talos-mcp-handlers/src/executions.rs::handle_analyze_execution_failure`
//! (~740 LoC of fetch + classify + patch + suggestion shaping).
//!
//! Architectural pattern: matches `talos-execution-orchestration`
//! (r295), `talos-workflow-manifest` (r302), `talos-replay-service`
//! (r303), and `talos-inline-compile-service` (r304). Arc-injected
//! dependencies, `thiserror` enum mapped to JSON-RPC codes via
//! `jsonrpc_code()`, typed input + outcome structs, and a
//! `user_facing_message()` accessor that collapses internal errors to a
//! generic message so the protocol response cannot leak schema or query
//! detail.
//!
//! Every operator-recognized string (the classification descriptions,
//! remediation step text, error messages, and the response field names)
//! is copied verbatim from the pre-extraction handler and locked by the
//! unit tests below.

#![forbid(unsafe_code)]

use std::sync::Arc;

use thiserror::Error;
use uuid::Uuid;

use talos_execution_repository::ExecutionRepository;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Service-level errors. Every variant maps to JSON-RPC `-32000` (the
/// pre-extraction handler emitted all of these through
/// `mcp_error(req_id, -32000, ...)`); the argument-shape errors
/// (`-32602`) stay in the protocol handler where `require_uuid` /
/// `validate_optional_bool` already own them.
#[derive(Debug, Error)]
pub enum FailureAnalysisError {
    /// Execution row missing or owned by a different user. Message is
    /// the literal pre-extraction string.
    #[error("Execution not found or access denied")]
    NotFound,

    /// Execution is not in a terminal-failure state. Message is the
    /// literal pre-extraction string (status echoed).
    #[error(
        "Execution status is '{status}' — only failed or cancelled executions can be analyzed."
    )]
    NotAnalyzable { status: String },

    /// The execution-row fetch failed. Detail is logged by the service;
    /// callers see the literal pre-extraction generic string.
    #[error("Database error fetching execution")]
    ExecutionFetch(#[source] anyhow::Error),

    /// The execution-events fetch failed. Detail is logged by the
    /// service; callers see the literal pre-extraction generic string.
    #[error("Database error fetching execution events")]
    EventsFetch(#[source] anyhow::Error),
}

impl FailureAnalysisError {
    /// Stable JSON-RPC error code for protocol wrappers.
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::NotFound
            | Self::NotAnalyzable { .. }
            | Self::ExecutionFetch(_)
            | Self::EventsFetch(_) => -32000,
        }
    }

    /// Callable-safe message for the protocol response. The two DB
    /// variants collapse to fixed generic strings (the `#[source]`
    /// detail never renders through `Display`), so the response cannot
    /// leak schema or query detail.
    pub fn user_facing_message(&self) -> String {
        self.to_string()
    }
}

// -----------------------------------------------------------------------------
// Input / outcome
// -----------------------------------------------------------------------------

/// Typed input for [`FailureAnalysisService::analyze`].
#[derive(Debug, Clone, Copy)]
pub struct AnalyzeFailureInput {
    pub execution_id: Uuid,
    pub user_id: Uuid,
    /// When true, attempt the config-field auto-fix and surface
    /// auth-error fix suggestions.
    pub apply_fix: bool,
    /// When true AND a fix was applied, stamp the auto-retry note on
    /// the report (the caller still triggers `retry_execution`
    /// explicitly).
    pub auto_retry: bool,
}

/// Analysis report. `report` is the JSON body the protocol layer
/// serializes; its shape is preserved byte-for-byte from the
/// pre-extraction handler (execution_id / workflow_id / status /
/// failed_node_count / failed_nodes / global_error /
/// apply_fix_available / tip, plus the optional fix_result /
/// auth_fix_suggestion / auto_retry_* fields).
#[derive(Debug, Clone)]
pub struct AnalyzeFailureOutcome {
    pub report: serde_json::Value,
}

// -----------------------------------------------------------------------------
// Pure helpers (unit-testable without a DB)
// -----------------------------------------------------------------------------

// MCP-1138 (2026-05-16): shared cap for the three sibling
// error-message classifiers below (`classify_error`,
// `extract_config_field`, `extract_secret_name_from_auth_error`).
// Each previously ran a full-input `to_lowercase()` clone followed
// by 4-15 substring scans on caller-controlled `raw_error` strings
// pulled from `execution_events.payload` (TEXT; Postgres caps at
// ~1 GB). A multi-MB workflow error message multiplied through
// per-failed-node iteration. 4 KiB matches the sibling cap in
// `talos_retry_intelligence::classify_error` (MCP-1135).
// Meaningful classification tokens (LLM/HTTP/host-allowlist,
// 'FIELD' / 'SECRET' identifiers) live in the first paragraph by
// construction; buried tokens past 4 KiB return the same
// "unknown" fall-through as MCP-1135.
pub fn truncate_for_classify(s: &str) -> &str {
    const MAX_BYTES: usize = 4096;
    if s.len() <= MAX_BYTES {
        return s;
    }
    let mut end = MAX_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Map a host-stamped [`talos_reason_class::Family`] onto this surface's
/// `(error_type, description)` vocabulary.
///
/// Split out of [`classify_error`] so the mapping is drivable directly by
/// test, and so the ONE place that decides "which remediation playbook does
/// this cause deserve" is visible in one screen.
///
/// # Why several families get a NEW bucket rather than an existing one
///
/// A bucket exists to select a [`remediation_steps`] playbook, so two causes
/// share a bucket only when the same instructions resolve both. Before this
/// existed, every `forbiddenhost` denial — at least five materially different
/// policies — answered `host_not_allowed`, whose playbook says to widen
/// `allowed_hosts`. For an SSRF block or a Tier-1 egress refusal that is not
/// merely unhelpful, it is advice that CANNOT work, given confidently.
///
/// Three families deliberately reuse an existing bucket, because the existing
/// playbook is already the right one:
/// * [`Family::HostAllowlist`] → `host_not_allowed` (this IS that bucket's
///   actual case, and it keeps the marked and unmarked forms together)
/// * [`Family::Transport`] → `network_error`
/// * [`Family::Timeout`] → `timeout`
/// * [`Family::SecretLookup`] → `missing_secret`
///
/// [`Family::HostAllowlist`]: talos_reason_class::Family::HostAllowlist
/// [`Family::Transport`]: talos_reason_class::Family::Transport
/// [`Family::Timeout`]: talos_reason_class::Family::Timeout
/// [`Family::SecretLookup`]: talos_reason_class::Family::SecretLookup
#[must_use]
pub fn classify_reason_class(family: talos_reason_class::Family) -> (&'static str, &'static str) {
    use talos_reason_class::Family as F;
    match family {
        F::Transport => (
            "network_error",
            "A network or infrastructure connection failed — the backing service may be unreachable.",
        ),
        F::Timeout => (
            "timeout",
            "The module exceeded its execution-time limit. Bump timeout_secs or split the work.",
        ),
        F::SecretLookup => (
            "missing_secret",
            "A required secret credential was not found in the vault.",
        ),
        F::CircuitOpen => (
            "circuit_open",
            "The worker's per-host circuit breaker is open: recent calls to this host failed enough times that the breaker is fast-failing new ones without attempting them. Nothing is misconfigured — the target host is being treated as down.",
        ),
        F::Cancelled => (
            "execution_cancelled",
            "The execution was cancelled while this call was in flight, so the host abandoned it. This is not a fault in the module.",
        ),
        F::ResponseCap => (
            "response_too_large",
            "The UPSTREAM response exceeded a host size cap (body bytes or header count) and was refused after the request went out. The remote endpoint is returning more than the sandbox will read.",
        ),
        F::RequestCap => (
            "request_too_large",
            "The module's OUTBOUND request exceeded a host size cap (body bytes or header count) and was refused before anything left the sandbox. Note this is the opposite direction from response_too_large.",
        ),
        F::MalformedUrl => (
            "invalid_url",
            "The URL the module built could not be used — it failed to parse, or exceeded the host's URL byte cap. This is an AUTHORING error, not a policy denial: no gate refused you.",
        ),
        F::InsecureScheme => (
            "insecure_scheme",
            "The host refused a plaintext http:// target. This is a SECURITY gate, not an allowlist miss — it is what stops a vault:// -substituted credential header going out in the clear. Widening allowed_hosts will not lift it.",
        ),
        F::CapabilityWorld => (
            "capability_world_denied",
            "The module's compiled capability_world does not grant this kind of call at all, so it was refused before any host policy was consulted. This is fixed on the MODULE, by recompiling into a world that grants it — not by changing any allowlist.",
        ),
        F::HostAllowlist => (
            "host_not_allowed",
            "The module tried to reach a host that's not in its allowed_hosts list.",
        ),
        F::PrivateAddress => (
            "ssrf_blocked",
            "SSRF gate: the target resolved (or was written) as a private, loopback, link-local, CGNAT or IPv4-mapped address, and the host refused to send the request. Adding the name to allowed_hosts does NOT lift this and is not meant to — the check runs on the resolved address, after the allowlist.",
        ),
        F::ActorEgressTier => (
            "egress_tier_denied",
            "The ACTOR's data-egress ceiling refused this destination — an external LLM provider, a public IP literal, or all public egress under local-only scope. This is a privacy control on the actor, not a capability of the module: no module-level change lifts it.",
        ),
        F::WriteCeiling => (
            "write_ceiling_denied",
            "The ACTOR's write ceiling refused this call — a mutating HTTP method, or (under strict egress) a read through a wildcard host match rather than a named host. Fixed on the actor, or by making the call read-only.",
        ),
        F::MethodAllowlist => (
            "method_not_allowed",
            "The HTTP verb the module used is not in its declared allowed_methods. The host is allowed; the method is not.",
        ),
        F::EgressBudget => (
            "egress_budget_exceeded",
            "A per-EXECUTION egress budget is spent: total outbound calls, calls to one host, or concurrent SSE streams. This is a Talos-side budget, NOT an upstream API rate limit — the request never left the sandbox, so waiting for a remote window to reset changes nothing.",
        ),
        F::GraphqlIntrospection => (
            "introspection_denied",
            "A GraphQL introspection query (__schema / __type) was refused — either by the actor's privacy class or by the operator-wide introspection block. Query the fields you need explicitly instead.",
        ),
    }
}

/// Classify a raw error message into a `(error_type, description)`
/// bucket. Strings preserved verbatim from the pre-extraction handler.
pub fn classify_error(msg: &str) -> (&'static str, &'static str) {
    // MCP-1138 (2026-05-16): cap input before to_lowercase to bound
    // the heap clone + per-pattern .contains scans. Same anti-pattern
    // as MCP-1135 (talos_retry_intelligence::classify_error). Error
    // messages come from `n.get("raw_error")` reads off
    // `execution_events.payload` (TEXT, ~1 GB Postgres ceiling); a
    // multi-MB workflow error message ran the full clone + 15+
    // substring scans per failed-node analysis. 4 KiB matches the
    // sibling cap; meaningful classification tokens live in the
    // first paragraph by construction (LLM/HTTP/host-allowlist
    // errors).
    let lower = truncate_for_classify(msg).to_lowercase();

    // ── The HOST-STAMPED cause, ahead of every prose gate ─────────────
    //
    // Since #714/#717 the worker appends `[reason_class=<token>]` to the
    // node-failure message at the site that actually refused the call. That
    // token is the ONLY authoritative statement about the cause in this
    // string: everything below is a substring guess at module prose, and the
    // WIT error enum the guest sees is payload-less, so a Tier-1 egress deny,
    // an SSRF block, a wrong capability world and a genuine host-allowlist
    // miss all render as the same opaque `forbiddenhost` / `invalidurl`.
    //
    // Hoisted FIRST for the same reason `talos_retry_intelligence` hoists its
    // marker arms: a host-stamped marker is authoritative and module prose is
    // not. Nothing UNMARKED moves — `token()` returns `None` and the chain
    // below runs byte-identically, which
    // `unmarked_messages_classify_exactly_as_before` pins as literals.
    //
    // An unknown token (an older controller reading a newer worker) also
    // falls through: `token_family` returns `None` unless the token is in the
    // closed set this build knows.
    if let Some((_, fam)) = talos_reason_class::token_family(&lower) {
        return classify_reason_class(fam);
    }

    // ── The UNMARKED circuit-breaker fast-fail ────────────────────────
    //
    // The breaker refuses a call two ways and only ONE of them carries a
    // marker. When it fires inside the host HTTP function the message is a
    // guest `networkerror` with `[reason_class=circuit-open]` appended, and
    // the arm above already answers `circuit_open`. When it fires in the
    // RETRY GATE — `talos_worker_runtime::runtime::circuit_open_message`,
    // which short-circuits before any call is attempted — the message is
    // plain prose with no marker at all, and matched nothing here: the same
    // cause reached the operator as two different answers, one of them
    // `runtime_error` / "An unexpected runtime error occurred inside the
    // module" for the platform's own protective refusal.
    //
    // Measured on the deployed stack 2026-09-04: 12 of the 20 `node_failed`
    // events that fell through this chain in 30 days were this string.
    //
    // The needles are the SAME PAIR the sibling controller-side classifier
    // `talos_retry_intelligence::classify_error` has keyed on since the
    // breaker shipped, and it hoists them for the same reason this does:
    // the fast-fail message may carry the last underlying error, which can
    // contain transient tokens ("connection refused", "timed out") that the
    // prose chain below would match first and answer `network_error` /
    // `timeout` for a call that was never made.
    //
    // No new vocabulary: `circuit_open` and its playbook already exist for
    // the marked form, and this arm answers with them.
    if lower.contains("circuit open") || lower.contains("circuit breaker open") {
        return classify_reason_class(talos_reason_class::Family::CircuitOpen);
    }

    // ── Most specific gates first ────────────────────────────────────
    // Order matters: each branch is `else if`; the first match wins.
    if lower.contains("output_schema enforcement fired")
        || lower.contains("output schema enforcement fired")
        || (lower.contains("required keys") && lower.contains("got prose"))
    {
        // Strict-JSON enforcement on an LLM Inference node returned
        // prose instead of the expected JSON shape. The actionable
        // fix is to tighten the SYSTEM_PROMPT — pre-empt the generic
        // "review logs / reproduce in sandbox" advice.
        (
            "output_schema_violation",
            "The LLM Inference node's OUTPUT_SCHEMA enforcement rejected the model's response because it wasn't strict JSON matching the required keys. The model returned prose / markdown / a JSON code fence instead of the bare object the schema demanded.",
        )
    } else if lower.contains("forbiddenhost")
        || lower.contains("forbidden host")
        || lower.contains("host not allowed")
        || lower.contains("host is not in the allowlist")
        || lower.contains("not in the node's allowlist")
    {
        (
            "host_not_allowed",
            "The module tried to reach a host that's not in its allowed_hosts list.",
        )
    } else if lower.contains("compilation failed")
        || lower.contains("compile error")
        || lower.contains("failed to compile")
        || (lower.contains("cargo") && lower.contains("error"))
    {
        (
            "module_compile_error",
            "A module failed to compile — bad Rust code, dep mismatch, or WIT drift.",
        )
    } else if lower.contains("expected value")
        || lower.contains("invalid type")
        || lower.contains("invalid json")
        || lower.contains("expected ident")
        || lower.contains("trailing characters")
        || (lower.contains("from_str") && lower.contains("error"))
        || (lower.contains("serde") && lower.contains("error"))
        || (lower.contains("expected") && lower.contains("found "))
    {
        (
            "json_parse",
            "JSON parsing failed — the input shape didn't match what the module expected.",
        )
    } else if lower.contains("secret not found")
        || lower.contains("secret missing")
        || lower.contains("key not found")
        || (lower.contains("secret") && lower.contains("not found"))
        || (lower.contains("secret") && lower.contains("notfound"))
        || (lower.contains("retrieve") && lower.contains("notfound"))
    {
        (
            "missing_secret",
            "A required secret credential was not found in the vault.",
        )
    } else if lower.contains("rate limit")
        || lower.contains("429")
        || lower.contains("too many requests")
    {
        (
            "rate_limit",
            "The module hit a rate limit on an external API.",
        )
    } else if lower.contains("out of fuel")
        || lower.contains("fuel exhausted")
        || (lower.contains("fuel") && lower.contains("limit"))
    {
        (
            "fuel_exhausted",
            "The WASM module ran out of fuel (compute budget). Bump max_fuel via fuel_budget on hot_update_module.",
        )
    } else if lower.contains("wasm trap") || lower.contains("trap: ") {
        (
            "wasm_trap",
            "The WASM module hit a fatal trap (panic, OOB access, invalid op).",
        )
    } else if lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("deadline exceeded")
        || lower.contains("execution exceeded")
    {
        (
            "timeout",
            "The module exceeded its execution-time limit. Bump timeout_secs or split the work.",
        )
    } else if lower.contains("connection refused")
        || lower.contains("connection timed out")
        || lower.contains("connectionfailed")      // redis / single-word connection error
        || lower.contains("connection failed")
        || lower.contains("dns")
        || (lower.contains("network") && lower.contains("error"))
        || lower.contains("no route to host")
        || lower.contains("failed to connect")
        || lower.contains("connect error")
    {
        (
            "network_error",
            "A network or infrastructure connection failed — the backing service may be unreachable.",
        )
    } else if lower.contains("missing field")
        || lower.contains("invalid config")
        || lower.contains("required field")
        || (lower.contains("config") && lower.contains("error"))
    {
        (
            "config_error",
            "A required configuration field is missing or invalid.",
        )
    } else if lower.contains("401") || lower.contains("invalid token") {
        (
            "http_401",
            "HTTP 401 Unauthorized — the credential is missing, expired, or rejected by the API.",
        )
    } else if lower.contains("403")
        || (lower.contains("forbidden") && !lower.contains("forbiddenhost"))
    {
        (
            "http_403",
            "HTTP 403 Forbidden — the credential is valid but lacks the required permission/scope.",
        )
    } else if lower.contains("404") || lower.contains("not found") {
        (
            "http_404",
            "HTTP 404 Not Found — the API endpoint or resource doesn't exist.",
        )
    } else if lower.contains("500")
        || lower.contains("502")
        || lower.contains("503")
        || lower.contains("504")
        || lower.contains("internal server error")
        || lower.contains("bad gateway")
        || lower.contains("gateway timeout")
    {
        (
            "http_5xx",
            "HTTP 5xx — the upstream API is unhealthy. Usually transient; retry with backoff.",
        )
    } else if lower.contains("unauthorized") || lower.contains("authentication failed") {
        // Generic Unauthorized that didn't match the more specific HTTP gates.
        // From the worker, this typically means a secrets gate failed
        // (capability world / allowlist / reserved-host). Use
        // test_secret_access(module_id, secret_path) to identify which gate.
        (
            "auth_error",
            "Authorization failed. If from a guest module's secrets call, run test_secret_access to identify whether the capability_world, allowed_secrets, or reserved-host gate failed.",
        )
    } else if lower.contains("postgres")
        || lower.contains("sqlite")
        || lower.contains("sql error")
        || lower.contains("database error")
        || lower.contains("connection pool")
    {
        ("database_error", "A database operation failed.")
    } else {
        // ── THE FALL-THROUGH ASSERTS NOTHING ──────────────────────────
        //
        // This arm is reached precisely when the message matched none of
        // the gates above, so the one thing that is known about it is that
        // its cause is NOT known. The previous answer — `runtime_error` /
        // "An unexpected runtime error occurred inside the module" —
        // stated a determinate cause AND a location for input the
        // classifier had explicitly failed to recognise, and it was wrong
        // about both far more often than not: of the 20 `node_failed`
        // events that reached this arm on the deployed stack in the 30
        // days to 2026-09-04, 19 were platform-side (a circuit-breaker
        // fast-fail, a rejected signed result, an unreadable job result)
        // and none was a fault inside a module.
        //
        // Coverage cannot fix that. Any pattern list has a fall-through,
        // and the next unrecognised cause would be misreported identically
        // — so the fall-through itself has to be honest. The crate's own
        // prose already was: `remediation_steps`' matching arm says "this
        // is the fall-through bucket, so the error text matched no
        // specific gate", and the MCP tool description says to treat the
        // bucket as "unexplained" rather than "explained". Only the two
        // machine-readable fields still claimed to know.
        //
        // Both sibling controller-side classifiers over the same strings
        // already answer honestly here — `talos_retry_intelligence`
        // returns `unknown` and `talos_ops_alerts_repository::self_monitor`
        // returns `other` / "unclassified failure". This surface, the only
        // one of the three that hands an operator a remediation playbook,
        // was the one asserting.
        (
            "unclassified",
            "The failure text matched no known cause, so this analysis does NOT know what went wrong — and in particular has NOT established that the fault is in the module. Platform-side causes arrive here as text this classifier does not recognise: a host-policy denial (recorded only in the worker's own log), a rejected or unreadable job result, a breaker or budget refusal from an older worker. Read raw_error and the worker's own lines before changing the module.",
        )
    }
}

/// Everything [`build_failed_node_diagnosis`] needs, and nothing it can read
/// from a database.
#[derive(Debug, Clone, Copy)]
pub struct NodeDiagnosis<'a> {
    /// Rendered `execution_events.node_id`, or `None` for the workflow-level
    /// entry (which reports `node_id: null`).
    pub node_id: Option<&'a str>,
    /// Display label for the report's `label` field.
    pub label: &'a str,
    /// Label interpolated into the remediation steps. Usually the same as
    /// `label`; the workflow-level entry deliberately differs.
    pub remediation_label: &'a str,
    /// The raw failure text this diagnosis is about.
    pub error_text: &'a str,
    /// The engine-stamped failure class, when the dispatcher recorded one.
    pub engine_error_class: Option<&'a str>,
    /// Whether to surface the host-stamped `reason_class` token when present.
    pub surface_reason_class: bool,
}

/// Build ONE `failed_nodes[]` entry. Pure — no repository, no clock, no I/O.
///
/// # Why this is a function and not four lines inside the loop
///
/// It was four lines inside the loop, and that made the CALL SITE
/// untestable: every test in this crate drove `classify_error` and
/// `remediation_steps` directly, so a mutation that classified correctly and
/// then wrote a hard-coded `("runtime_error", "An unexpected runtime error
/// occurred inside the module.")` into the report — i.e. the exact defect
/// this change exists to remove, fully restored — was MEASURED to leave every
/// test in this crate green. That is the silent direction: green tests over a
/// report that misdiagnoses every failure.
///
/// Extracting it puts the whole classification-to-report mapping in one pure
/// function that a test can drive and read the FIELDS of. `analyze` keeps only
/// what genuinely needs the database (the fuel-history attachment).
///
/// The remaining, stated limit: a mutation inside `analyze` that ignored this
/// function's return value entirely would still survive, because proving that
/// needs a repository. This shrinks the untested surface; it does not close it.
#[must_use]
pub fn build_failed_node_diagnosis(input: NodeDiagnosis<'_>) -> serde_json::Value {
    let NodeDiagnosis {
        node_id,
        label,
        remediation_label,
        error_text,
        engine_error_class,
        surface_reason_class,
    } = input;

    let (error_type, description) = classify_error(error_text);
    let steps = remediation_steps(error_type, remediation_label);

    // Surface the engine-stamped failure class alongside our string-regex
    // classification. They answer different questions:
    //   - `engine_error_class` ("non-transient", "transient", classifier
    //     tags like "not_found") tells callers WHY retries were / weren't
    //     attempted — authoritative, populated by the NATS dispatcher.
    //   - `error_type` (ours, regex-based) classifies into user-actionable
    //     buckets (missing_secret / rate_limit / wasm_trap / etc.) with
    //     matching remediation_steps.
    // Both being present lets agents pick whichever signal they need.
    let mut failed_node = serde_json::json!({
        "node_id": node_id,
        "label": label,
        "error_type": error_type,
        "error_description": description,
        "raw_error": error_text,
        "remediation_steps": steps,
    });
    if let Some(ec) = engine_error_class {
        if let Some(obj) = failed_node.as_object_mut() {
            obj.insert("engine_error_class".to_string(), serde_json::json!(ec));
        }
    }

    // The exact host-stamped token, when the worker put one on this
    // message. `error_type` is the REMEDIATION bucket and deliberately
    // merges causes that share a fix (`no-allowlist` and
    // `allowed-hosts` are one bucket); this field is the precise
    // cause, so an operator or agent that wants to distinguish them
    // does not have to re-parse `raw_error`. Present only when a
    // marker is present, exactly like `engine_error_class` — never a
    // fabricated "unknown".
    if surface_reason_class {
        if let Some(tok) =
            talos_reason_class::token(&truncate_for_classify(error_text).to_lowercase())
        {
            if let Some(obj) = failed_node.as_object_mut() {
                obj.insert("reason_class".to_string(), serde_json::json!(tok));
            }
        }
    }

    failed_node
}

/// Remediation-step playbook per error bucket. Strings preserved
/// verbatim from the pre-extraction handler.
pub fn remediation_steps(error_type: &str, module_label: &str) -> Vec<serde_json::Value> {
    match error_type {
        "output_schema_violation" => vec![
            serde_json::json!({ "step": 1, "action": "inspect_response", "description": format!("Pull the full LLM response that was rejected for node '{}' — get_execution_logs surfaces the model's literal output so you can see exactly which fence/prose form it returned.", module_label), "tool": "get_execution_logs" }),
            serde_json::json!({ "step": 2, "action": "tighten_system_prompt", "description": "Update the node's SYSTEM_PROMPT config to instruct STRICT JSON output: 'Output STRICT JSON with EXACTLY these top-level keys: …. No prose outside the JSON. No markdown code fence around the JSON.' Use update_node_config with the new prompt.", "tool": "update_node_config" }),
            serde_json::json!({ "step": 3, "action": "lower_temperature", "description": "If the model intermittently lapses into prose, drop TEMPERATURE to 0 (or as low as the model supports) to make schema-conformant output deterministic.", "tool": "update_node_config" }),
            serde_json::json!({ "step": 4, "action": "retry", "description": "Retry the execution after the prompt change. SCHEMA enforcement is best-effort defence; a tightened prompt usually fixes it without needing schema relaxation.", "tool": "retry_execution" }),
        ],
        "host_not_allowed" => vec![
            serde_json::json!({ "step": 1, "action": "inspect_worker_logs", "description": format!("Confirm WHICH gate refused node '{}' with tail_worker_logs — the worker records the refusal as `[host:<policy>] <capability> denied by policy '<policy>' (target: ...)`, naming the policy. allowed_hosts is only one of the policies that can deny; an insecure-scheme or tier-1 egress refusal reads identically from the module's downstream error, and widening allowed_hosts will not fix those.", module_label), "tool": "tail_worker_logs" }),
            serde_json::json!({ "step": 2, "action": "identify_target_host", "description": format!("Inspect node '{}' source code or HTTP request URL — find the hostname it tried to reach.", module_label), "tool": "get_module_info" }),
            serde_json::json!({ "step": 3, "action": "extend_allowed_hosts", "description": "If step 1 named the allowed_hosts policy: add the host with update_module_hosts (module-level, replaces the list, no recompile). hot_update_module also works and is the right call if you are changing the source anyway. NOT update_node_config — allowed_hosts is a module setting, not node config. Use ['*'] to allow all hosts (not recommended for production).", "tool": "update_module_hosts" }),
            serde_json::json!({ "step": 4, "action": "retry", "description": "Retry the execution once the module's host list is updated.", "tool": "retry_execution" }),
        ],
        "module_compile_error" => vec![
            serde_json::json!({ "step": 1, "action": "review_error", "description": "Read the compiler error in raw_error — rustc errors include line numbers.", "tool": null }),
            serde_json::json!({ "step": 2, "action": "lint_first", "description": "Run lint_sandbox on the new source code (~3s) to catch type errors before paying the 30-60s compile.", "tool": "lint_sandbox" }),
            serde_json::json!({ "step": 3, "action": "scaffold", "description": "Compare against the canonical scaffold to spot drift.", "tool": "get_rust_scaffold" }),
        ],
        "json_parse" => vec![
            serde_json::json!({ "step": 1, "action": "inspect_input", "description": format!("Get the actual input shape that reached node '{}' — the parser expected something different.", module_label), "tool": "get_node_io" }),
            serde_json::json!({ "step": 2, "action": "check_upstream", "description": "Trace which upstream node produced this output — the shape may have changed silently.", "tool": "get_execution_status" }),
            serde_json::json!({ "step": 3, "action": "fix_parser", "description": "Either change the module's parser to match the actual shape, or fix upstream to emit the expected shape. Untyped serde_json::Value is more forgiving but burns 3-10x more fuel — use typed structs for hot paths.", "tool": null }),
        ],
        "fuel_exhausted" => vec![
            serde_json::json!({ "step": 1, "action": "estimate_payload", "description": format!("How big is the input to node '{}'? Each KB costs ~2 fuel; 60K per item baseline.", module_label), "tool": "get_node_io" }),
            serde_json::json!({ "step": 2, "action": "bump_fuel", "description": "hot_update_module with fuel_budget: {expected_items, bytes_per_item, llm_output_bytes ≈ 3000 for LLM nodes, safety_multiplier: 2.0-3.0} — formula clamps to [1M, 50M].", "tool": "hot_update_module" }),
            serde_json::json!({ "step": 3, "action": "switch_to_typed", "description": "If the module uses serde_json::Value parsing on a large payload, switching to typed #[derive(Deserialize)] structs is 3-10x cheaper than bumping fuel.", "tool": null }),
        ],
        "timeout" => vec![
            serde_json::json!({ "step": 1, "action": "review_timeout", "description": format!("Check the timeout_secs setting on node '{}'. Call get_workflow with view='raw_json' to see the node's data verbatim.", module_label), "tool": "get_workflow" }),
            serde_json::json!({ "step": 2, "action": "bump_timeout", "description": "Re-add the node with a higher timeout_secs (default 60). LLM nodes typically need 30-90s; large HTTP fetches 30-60s; expensive SQL 60-120s.", "tool": "add_node_to_workflow" }),
            serde_json::json!({ "step": 3, "action": "split_work", "description": "If the timeout reflects genuine workload size (e.g., processing 1000 items), consider splitting into a loop or fan-out/fan-in pattern so each node has bounded work.", "tool": null }),
        ],
        "http_401" => vec![
            serde_json::json!({ "step": 1, "action": "verify_secret_present", "description": format!("Check that the credential node '{}' uses still exists in the vault.", module_label), "tool": "list_secrets" }),
            serde_json::json!({ "step": 2, "action": "test_secret_access", "description": "Run test_secret_access(module_id, secret_path) to confirm the module is allowed to read it.", "tool": "test_secret_access" }),
            serde_json::json!({ "step": 3, "action": "rotate", "description": "If the credential is present and allowed but still 401s, the upstream key has expired or been revoked. Rotate the secret in the dashboard (Settings → Secrets) — secret writes require 2FA and aren't available through MCP.", "tool": null }),
        ],
        "http_403" => vec![
            serde_json::json!({ "step": 1, "action": "check_scopes", "description": "403 means authn worked but the credential lacks the required scope/permission. Check the upstream API's docs for the operation's required scopes.", "tool": null }),
            serde_json::json!({ "step": 2, "action": "regenerate_token", "description": "If the scopes look right but the API disagrees, regenerate the token with the necessary scopes selected, then update the value in the dashboard (Settings → Secrets) — secret writes require 2FA and aren't available through MCP.", "tool": null }),
        ],
        "http_404" => vec![
            serde_json::json!({ "step": 1, "action": "verify_endpoint", "description": format!("Inspect node '{}' source — confirm the URL/path is correct. 404 often means a typo or stale resource id.", module_label), "tool": "get_module_info" }),
            serde_json::json!({ "step": 2, "action": "check_input", "description": "If the URL is templated from upstream input (e.g. /repos/{owner}/{repo}), the upstream may have produced a wrong/missing field.", "tool": "get_node_io" }),
        ],
        "http_5xx" => vec![
            serde_json::json!({ "step": 1, "action": "wait_and_retry", "description": "5xx is almost always upstream-side; the API is unhealthy or overloaded. Wait a minute and retry.", "tool": "retry_execution" }),
            serde_json::json!({ "step": 2, "action": "check_status_page", "description": "Check the upstream provider's status page (if any) for an ongoing incident before debugging your code.", "tool": null }),
            serde_json::json!({ "step": 3, "action": "tighten_retries", "description": "If 5xx is recurring, set retry_count: 3 and retry_backoff_ms: 2000 on the node so transient failures self-heal.", "tool": "add_node_to_workflow" }),
        ],
        "missing_secret" => vec![
            serde_json::json!({ "step": 1, "action": "identify_secret", "description": format!("Check which secret key_path node '{}' expects — use get_workflow_quickstart to list required secrets.", module_label), "tool": "get_workflow_quickstart" }),
            serde_json::json!({ "step": 2, "action": "test_gates", "description": "test_secret_access(module_id, secret_path) tells you whether the path is in the vault, in the allowlist, and within the capability world — all in one call.", "tool": "test_secret_access" }),
            serde_json::json!({ "step": 3, "action": "provision_secret", "description": "Store the credential in the dashboard (Settings → Secrets) using the correct key_path — secret writes require 2FA and aren't available through MCP.", "tool": null }),
            serde_json::json!({ "step": 4, "action": "retry", "description": "Retry the execution after provisioning the secret.", "tool": "retry_execution" }),
        ],
        "rate_limit" => vec![
            serde_json::json!({ "step": 1, "action": "check_rate_limit", "description": format!("Review the rate limit setting for node '{}' and the external API's limits.", module_label), "tool": "get_module_rate_limit" }),
            serde_json::json!({ "step": 2, "action": "adjust_rate_limit", "description": "Lower requests_per_minute with set_module_rate_limit or add a delay between executions.", "tool": "set_module_rate_limit" }),
            serde_json::json!({ "step": 3, "action": "retry", "description": "Wait for the rate limit window to reset, then retry.", "tool": "retry_execution" }),
        ],
        "wasm_trap" => vec![
            serde_json::json!({ "step": 1, "action": "increase_fuel", "description": "Increase WASM_FUEL_LIMIT env var or set a higher per-node timeout if the module was cut off mid-processing.", "tool": null }),
            serde_json::json!({ "step": 2, "action": "check_input_size", "description": "Large input payloads can exhaust fuel — verify the data passed to this node is reasonably sized.", "tool": "get_node_output" }),
            serde_json::json!({ "step": 3, "action": "test_sandbox", "description": "Test the module in isolation with run_sandbox to reproduce the trap with a minimal input.", "tool": "run_sandbox" }),
        ],
        "network_error" => vec![
            serde_json::json!({ "step": 1, "action": "check_connectivity", "description": format!("Verify the external service node '{}' connects to is reachable from the worker.", module_label), "tool": null }),
            serde_json::json!({ "step": 2, "action": "check_allowed_hosts", "description": "Ensure the module's allowed_hosts list includes the target domain.", "tool": "get_module_info" }),
            serde_json::json!({ "step": 3, "action": "retry", "description": "If the outage is transient, retry the execution.", "tool": "retry_execution" }),
        ],
        "config_error" => vec![
            serde_json::json!({ "step": 1, "action": "check_config", "description": format!("Review the config for node '{}' — a required field may be missing or set to an incorrect type.", module_label), "tool": "get_workflow_quickstart" }),
            serde_json::json!({ "step": 2, "action": "update_config", "description": "Set the missing config key with update_node_config.", "tool": "update_node_config" }),
            serde_json::json!({ "step": 3, "action": "test", "description": "Re-test the workflow after fixing the config.", "tool": "test_workflow_draft" }),
        ],
        "auth_error" => vec![
            serde_json::json!({ "step": 1, "action": "test_secret_gates", "description": format!("If node '{}' calls secrets::get_secret directly, run test_secret_access(module_id, secret_path) — it reports which of the four gates failed (capability_world, allowed_secrets, reserved-host, vault presence) without needing a redeploy.", module_label), "tool": "test_secret_access" }),
            serde_json::json!({ "step": 2, "action": "check_secret", "description": "If this is a vault:// header substitution, verify the secret is still present and not expired.", "tool": "list_secrets" }),
            serde_json::json!({ "step": 3, "action": "re_provision_secret", "description": "Generate a new token/key and update the secret in the dashboard (Settings → Secrets) — secret writes require 2FA and aren't available through MCP.", "tool": null }),
            serde_json::json!({ "step": 4, "action": "retry", "description": "Retry after updating the credential.", "tool": "retry_execution" }),
        ],
        "database_error" => vec![
            serde_json::json!({ "step": 1, "action": "check_connection", "description": format!("Verify the database connection URL secret used by node '{}' is correct and the DB is reachable.", module_label), "tool": null }),
            serde_json::json!({ "step": 2, "action": "check_secret", "description": "Confirm the database/connection_url secret is provisioned (via the dashboard Settings → Secrets — secret writes require 2FA and aren't available through MCP).", "tool": null }),
            serde_json::json!({ "step": 3, "action": "retry", "description": "Retry after fixing the connection.", "tool": "retry_execution" }),
        ],
        // ── Host-stamped `[reason_class=…]` denial playbooks ──────────────
        //
        // One arm per remediation, which is the whole point: before these
        // existed every one of these causes answered `host_not_allowed` and
        // was told to widen `allowed_hosts`. That instruction resolves
        // exactly ONE of them. For an SSRF block, a Tier-1 egress refusal or
        // a capability-world miss it is advice that cannot work.
        //
        // Every arm's step 1 is `tail_worker_logs`, because the marker names
        // the POLICY but the worker's own `[host:<policy>] … (target: …)`
        // line is the only place the TARGET and the precise family variant
        // (`private-ip-cgnat` vs `private-ip-nat64`, `tier1-introspection` vs
        // `env-introspection-block`) appear — those are collapsed to a family
        // prefix on the wire so the closed token set stays closed.
        "circuit_open" => vec![
            serde_json::json!({ "step": 1, "action": "inspect_worker_logs", "description": format!("Read the worker's lines for node '{}' with tail_worker_logs — the breaker records which host it opened on and the underlying failures that opened it. The breaker is a SYMPTOM: something made repeated calls to that host fail.", module_label), "tool": "tail_worker_logs" }),
            serde_json::json!({ "step": 2, "action": "check_target_health", "description": "Check whether the target host is actually healthy (status page, direct curl from outside Talos). The breaker exists so a down host stops consuming worker capacity; it is not a Talos misconfiguration.", "tool": null }),
            serde_json::json!({ "step": 3, "action": "retry", "description": "The breaker closes on its own cooldown. Once the host is healthy, retry — do NOT add retry_count for this: a fast-fail is deliberately non-transient, so in-execution retries only burn attempts.", "tool": "retry_execution" }),
        ],
        "execution_cancelled" => vec![
            serde_json::json!({ "step": 1, "action": "confirm_cancellation", "description": format!("The in-flight call from node '{}' was abandoned because the EXECUTION was cancelled — this is not a fault in the module. Confirm who cancelled it and when.", module_label), "tool": "get_execution_status" }),
            serde_json::json!({ "step": 2, "action": "rerun_if_unintended", "description": "If the cancellation was unintended (an operator cancel, a concurrency-limit sweep), simply re-run. There is nothing to fix in the workflow.", "tool": "retry_execution" }),
        ],
        "response_too_large" => vec![
            serde_json::json!({ "step": 1, "action": "inspect_worker_logs", "description": format!("Read the worker's lines for node '{}' with tail_worker_logs — they name which cap tripped (response body bytes vs. header count) and the target host.", module_label), "tool": "tail_worker_logs" }),
            serde_json::json!({ "step": 2, "action": "narrow_the_request", "description": "The request DID go out; the upstream answered with more than the sandbox will read. Narrow the response at the source: page the endpoint, ask for fewer fields (Gmail format=metadata, a Jira `fields` param), or filter server-side. This is cheaper than any cap change and also cuts fuel.", "tool": "get_module_info" }),
            serde_json::json!({ "step": 3, "action": "retry", "description": "Retry once the module requests a smaller response.", "tool": "retry_execution" }),
        ],
        "request_too_large" => vec![
            serde_json::json!({ "step": 1, "action": "inspect_worker_logs", "description": format!("Read the worker's lines for node '{}' with tail_worker_logs — they name which OUTBOUND cap tripped (request body bytes vs. header count). Note the direction: this is what the module SENT, not what it received.", module_label), "tool": "tail_worker_logs" }),
            serde_json::json!({ "step": 2, "action": "inspect_what_it_sent", "description": format!("Look at the input that reached node '{}' — an oversized outbound body is almost always an upstream node handing it a larger payload than the design assumed.", module_label), "tool": "get_node_io" }),
            serde_json::json!({ "step": 3, "action": "shrink_or_batch", "description": "Split the send into batches, or trim the payload before it reaches this node. Nothing left the sandbox, so no upstream state changed — a batched re-send is safe.", "tool": null }),
        ],
        "invalid_url" => vec![
            serde_json::json!({ "step": 1, "action": "inspect_resolved_input", "description": format!("No policy refused this — the URL node '{}' built could not be parsed, or was longer than the host's URL byte cap. Look at the resolved config and input the node actually ran with.", module_label), "tool": "get_node_io" }),
            serde_json::json!({ "step": 2, "action": "read_the_builder", "description": format!("Read how node '{}' assembles its URL — the usual causes are an unsubstituted template placeholder, a missing upstream field concatenated as an empty string, or an unencoded query value.", module_label), "tool": "get_module_source" }),
            serde_json::json!({ "step": 3, "action": "fix_config_or_source", "description": "Fix the config value with update_node_config if the URL comes from config; fix the builder with hot_update_module if it is assembled in source.", "tool": "update_node_config" }),
            serde_json::json!({ "step": 4, "action": "retry", "description": "Retry once the URL resolves correctly.", "tool": "retry_execution" }),
        ],
        "insecure_scheme" => vec![
            serde_json::json!({ "step": 1, "action": "inspect_worker_logs", "description": format!("Read the worker's lines for node '{}' with tail_worker_logs — they name the plaintext target that was refused. This is a SECURITY gate, not an allowlist miss: widening allowed_hosts will not lift it.", module_label), "tool": "tail_worker_logs" }),
            serde_json::json!({ "step": 2, "action": "switch_to_https", "description": "Change the target to https://. The gate exists because a vault:// -substituted credential header on a plaintext request goes out in the clear — so the correct fix is always TLS, never an exemption.", "tool": "update_node_config" }),
            serde_json::json!({ "step": 3, "action": "retry", "description": "Retry once the target is https://.", "tool": "retry_execution" }),
        ],
        "capability_world_denied" => vec![
            serde_json::json!({ "step": 1, "action": "inspect_worker_logs", "description": format!("Read the worker's lines for node '{}' with tail_worker_logs — they name the capability the module attempted and the world it was compiled with.", module_label), "tool": "tail_worker_logs" }),
            serde_json::json!({ "step": 2, "action": "check_declared_world", "description": format!("Confirm the world node '{}' was compiled with. The refusal happened BEFORE any host policy ran, so no allowlist change is relevant.", module_label), "tool": "get_module_info" }),
            serde_json::json!({ "step": 3, "action": "pick_the_right_world", "description": "Look up which world grants the capability the module needs, and take the least-privileged one that does.", "tool": "describe_capability_world" }),
            serde_json::json!({ "step": 4, "action": "check_your_ceiling", "description": "Confirm your own capability ceiling permits that world — if it does not, the recompile will be refused too, and the ceiling is the real blocker.", "tool": "get_my_capability_ceiling" }),
            serde_json::json!({ "step": 5, "action": "recompile", "description": "Recompile the module into that world with hot_update_module. capability_world is baked at compile time; there is no runtime setting for it.", "tool": "hot_update_module" }),
        ],
        "ssrf_blocked" => vec![
            serde_json::json!({ "step": 1, "action": "inspect_worker_logs", "description": format!("Read the worker's lines for node '{}' with tail_worker_logs — they name the precise SSRF variant (loopback, link-local, CGNAT, IPv4-mapped, NAT64) and the target. The wire marker collapses those to one family, so this is the only place the variant appears.", module_label), "tool": "tail_worker_logs" }),
            serde_json::json!({ "step": 2, "action": "trace_the_target", "description": format!("Find where node '{}' got that target. The check runs on the RESOLVED address, after the allowlist — so a public hostname whose DNS answer is private trips it just as a literal 10.x does.", module_label), "tool": "get_node_io" }),
            serde_json::json!({ "step": 3, "action": "point_at_a_public_endpoint", "description": "Point the node at a routable public endpoint. Do NOT try to lift this by widening allowed_hosts — the SSRF check runs after it and is not an allowlist. If the module genuinely needs to reach a service inside the cluster, that is an architecture change (a controller-side integration), not a module setting.", "tool": null }),
        ],
        "egress_tier_denied" => vec![
            serde_json::json!({ "step": 1, "action": "inspect_worker_logs", "description": format!("Read the worker's lines for node '{}' with tail_worker_logs — they say WHICH egress control fired: the external-LLM-provider deny, the public-IP-literal deny, or the blanket local-egress-only resolver gate. The three have different fixes.", module_label), "tool": "tail_worker_logs" }),
            serde_json::json!({ "step": 2, "action": "read_the_actor", "description": "Read the bound actor's max_llm_tier and egress_scope. This is a PRIVACY control on the actor, not a capability of the module — no allowed_hosts, capability_world or node-config change lifts it.", "tool": "get_actor_summary" }),
            serde_json::json!({ "step": 3, "action": "allow_public_egress", "description": "If the actor is tier1 and the target is a legitimate public API (not an LLM provider), set egress_scope=public. That is the house pattern for a privacy actor: tier1 keeps the LLM local while public egress reaches declared allowed_hosts.", "tool": "set_actor_egress_scope" }),
            serde_json::json!({ "step": 4, "action": "reconsider_the_llm_tier", "description": "If the target IS an external LLM provider, the actor is tier1 on purpose — its data must not leave the host. Either point the node at the local Ollama tier, or make a deliberate decision to raise the ceiling to tier2 (which permits that actor's data to leave).", "tool": "set_actor_llm_tier_ceiling" }),
            serde_json::json!({ "step": 5, "action": "retry", "description": "Retry once the actor's ceiling matches the intent.", "tool": "retry_execution" }),
        ],
        "write_ceiling_denied" => vec![
            serde_json::json!({ "step": 1, "action": "inspect_worker_logs", "description": format!("Read the worker's lines for node '{}' with tail_worker_logs — they say whether a mutating METHOD was refused, or (under strict egress) a read admitted only by a wildcard host match rather than a named host.", module_label), "tool": "tail_worker_logs" }),
            serde_json::json!({ "step": 2, "action": "read_the_actor", "description": "Read the bound actor's write ceiling. A read-only actor refusing a POST is the control working as designed — confirm the call SHOULD be mutating before changing anything.", "tool": "get_actor_summary" }),
            serde_json::json!({ "step": 3, "action": "decide_deliberately", "description": "Either make the call read-only (usually the right answer for a reporting workflow), or raise the actor's write ceiling with set_actor_write_ceiling if the mutation is genuinely intended. For the strict-egress case, naming the host explicitly in allowed_hosts instead of matching it by wildcard also resolves it.", "tool": "set_actor_write_ceiling" }),
            serde_json::json!({ "step": 4, "action": "retry", "description": "Retry once the ceiling and the call agree.", "tool": "retry_execution" }),
        ],
        "method_not_allowed" => vec![
            serde_json::json!({ "step": 1, "action": "inspect_worker_logs", "description": format!("Read the worker's lines for node '{}' with tail_worker_logs — they name the verb that was refused. The HOST was allowed; the METHOD was not.", module_label), "tool": "tail_worker_logs" }),
            serde_json::json!({ "step": 2, "action": "check_declared_methods", "description": format!("Check node '{}''s module allowed_methods list against the verb it issued.", module_label), "tool": "get_module_info" }),
            serde_json::json!({ "step": 3, "action": "declare_the_method", "description": "Add the verb with update_module_methods. Declare the verbs you actually use rather than clearing the list: an EMPTY allowed_methods means 'allow everything' AND forfeits the automatic read-only retry default, so new nodes from that module get retry_count 0.", "tool": "update_module_methods" }),
            serde_json::json!({ "step": 4, "action": "retry", "description": "Retry once the method is declared.", "tool": "retry_execution" }),
        ],
        "egress_budget_exceeded" => vec![
            serde_json::json!({ "step": 1, "action": "inspect_worker_logs", "description": format!("Read the worker's lines for node '{}' with tail_worker_logs — they name which per-execution budget was spent: total outbound calls, calls to one host, or concurrent SSE streams.", module_label), "tool": "tail_worker_logs" }),
            serde_json::json!({ "step": 2, "action": "count_the_calls", "description": format!("Look at what node '{}' was iterating over. A spent call budget almost always means an unbounded loop over an upstream collection that grew — cap the collection (take(N)) rather than raising the budget.", module_label), "tool": "get_node_io" }),
            serde_json::json!({ "step": 3, "action": "do_not_treat_as_rate_limit", "description": "This is a TALOS-side per-execution budget, not an upstream API rate limit: the request never left the sandbox. Waiting for a remote window to reset, or lowering set_module_rate_limit, changes nothing. For the SSE case, close streams when done — that cap is concurrency, and it clears on close.", "tool": null }),
        ],
        "introspection_denied" => vec![
            serde_json::json!({ "step": 1, "action": "inspect_worker_logs", "description": format!("Read the worker's lines for node '{}' with tail_worker_logs — they say whether the actor's privacy class refused the introspection, or the operator-wide introspection block did.", module_label), "tool": "tail_worker_logs" }),
            serde_json::json!({ "step": 2, "action": "find_the_introspection", "description": format!("Find the __schema / __type selection in node '{}''s query. Client libraries sometimes send one automatically on first use.", module_label), "tool": "get_module_source" }),
            serde_json::json!({ "step": 3, "action": "query_explicitly", "description": "Replace the introspection with an explicit field selection. Introspection reveals a third-party schema's shape to the actor, which is exactly what the privacy class is refusing; hand-writing the query is the intended path, not an exemption.", "tool": null }),
        ],
        _ => vec![
            serde_json::json!({ "step": 1, "action": "inspect_worker_logs", "description": format!("Read the WORKER's own log lines for node '{}' with tail_worker_logs. This is the fall-through bucket, so the error text matched no specific gate — and a host-policy denial is exactly that case: `[host:<policy>] <capability> denied by policy '<policy>' (target: ...)` is written by the worker at WARN, lands in module_execution_logs, and is NOT in the engine event stream this analysis classified. The module's own downstream error (an 'invalidurl', a bare HTTP failure) is what you were shown; the control that actually fired is only here.", module_label), "tool": "tail_worker_logs" }),
            serde_json::json!({ "step": 2, "action": "inspect_logs", "description": format!("Review the engine's node-state event stream for node '{}' in get_execution_logs — node_input carries the resolved config the node actually ran with.", module_label), "tool": "get_execution_logs" }),
            serde_json::json!({ "step": 3, "action": "trace", "description": "Use get_execution_status(detail: true) for a full data-flow view of what succeeded before the failure.", "tool": "get_execution_status" }),
            serde_json::json!({ "step": 4, "action": "test_sandbox", "description": "ONLY IF steps 1-3 point at the module: reproduce in isolation using run_sandbox with the same input data. This bucket means the cause is UNKNOWN — it is NOT a finding that the module is at fault. A circuit-breaker fast-fail, a cancelled execution, a rejected signed result and a host-policy denial all arrive here as text this classifier does not recognise, and reproducing a module that is fine will only show that it is fine.", "tool": "run_sandbox" }),
        ],
    }
}

/// Extract a config field name from a config-error message. Returns
/// `None` when no known pattern matches.
pub fn extract_config_field(raw_error: &str) -> Option<String> {
    // Try to extract field name from patterns like:
    //   "missing field 'FIELD'"  — sqlx / serde style
    //   "Missing 'FIELD' in config" — module runtime style (most common in practice)
    //   "required field 'FIELD'"
    //   "invalid config key 'FIELD'"
    // All comparisons are case-insensitive; indexing into the original string is safe
    // because all matched characters are ASCII and byte-lengths match.
    //
    // MCP-1138: cap input before to_lowercase + repeated .find scans.
    // Same anti-pattern + cap as `classify_error` above and the
    // MCP-1135 sibling in talos_retry_intelligence. Field-extraction
    // tokens live in the first paragraph by construction; if a
    // pathological 1 MB raw_error buries the field past 4 KiB, we
    // return None and the operator falls through to the manual fix
    // path — same trade-off MCP-1135 made.
    let raw_error = truncate_for_classify(raw_error);
    let patterns = [
        "missing '",
        "missing field '",
        "missing field \"",
        "required field '",
        "required field \"",
        "invalid config key '",
        "invalid config key \"",
    ];
    let lower = raw_error.to_lowercase();
    for pat in &patterns {
        if let Some(start) = lower.find(pat) {
            let after = &raw_error[start + pat.len()..];
            let end = after.find(['\'', '"', ' ', ':']).unwrap_or(after.len());
            let field = after[..end].trim().to_string();
            if !field.is_empty() {
                return Some(field);
            }
        }
    }
    None
}

/// Auth-error auto-fix helper: extract the secret name referenced in an
/// auth-error message so the fix suggestion can name the row to touch.
pub fn extract_secret_name_from_auth_error(msg: &str) -> Option<String> {
    // MCP-1138: cap input before to_lowercase + repeated .find scans.
    // Same anti-pattern + cap as sibling `classify_error` /
    // `extract_config_field` above. Secret-name tokens live in the
    // first paragraph of an auth error; tradeoff matches MCP-1135.
    let msg = truncate_for_classify(msg);
    let lower = msg.to_lowercase();
    for pattern in &["secret '", "key '", "token '", "credential '"] {
        if let Some(start) = lower.find(pattern) {
            let after = &msg[start + pattern.len()..];
            let end = after.find(['\'', '"', ':', ' ']).unwrap_or(0);
            if end > 0 {
                let name = after[..end].trim().to_string();
                if !name.is_empty() {
                    return Some(name);
                }
            }
        }
    }
    None
}

/// Build an `engine node UUID → display label` map from a workflow's
/// `graph_json`. `execution_events.node_id` carries the value
/// [`talos_workflow_engine_core::engine_node_uuid`] derives from the graph's
/// string node id (`"node-1"`); the label resolved via `node.data.label` is
/// the safe bridge back to human-readable names.
///
/// The derivation is NOT re-implemented here. A private copy that drifts from
/// the executor's does not fail loudly — the map keys stop matching any
/// `node_id` on disk, every lookup falls through to the raw UUID, and the
/// surface reads as "this node has no label" rather than "the mapping broke".
pub fn build_node_display_label_map(
    graph_str: Option<String>,
) -> std::collections::HashMap<Uuid, String> {
    let mut map = std::collections::HashMap::new();
    if let Some(gj) = graph_str {
        if let Ok(graph) = serde_json::from_str::<serde_json::Value>(&gj) {
            if let Some(nodes) = graph.get("nodes").and_then(|n| n.as_array()) {
                for node in nodes {
                    if let Some(rf_id) = node.get("id").and_then(|v| v.as_str()) {
                        let node_uuid = talos_workflow_engine_core::engine_node_uuid(rf_id);
                        let label = node
                            .get("data")
                            .and_then(|d| d.get("label"))
                            .and_then(|l| l.as_str())
                            .unwrap_or(rf_id)
                            .to_string();
                        map.insert(node_uuid, label);
                    }
                }
            }
        }
    }
    map
}

fn json_optional_string(obj: &serde_json::Value, field: &str) -> Option<String> {
    obj.get(field).and_then(|v| v.as_str()).map(String::from)
}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/// Failure-analysis orchestration. One shared instance backs the MCP
/// `analyze_execution_failure` tool and is ready to back a future
/// GraphQL surface — same Arc, same classification + fix flow.
pub struct FailureAnalysisService {
    execution_repo: Arc<ExecutionRepository>,
}

impl FailureAnalysisService {
    pub fn new(execution_repo: Arc<ExecutionRepository>) -> Self {
        Self { execution_repo }
    }

    /// Analyze a failed/cancelled execution: per-node diagnoses with
    /// remediation playbooks, optional config-field auto-fix, and
    /// auth-error fix suggestions. Report shape preserved byte-for-byte
    /// from the pre-extraction handler.
    pub async fn analyze(
        &self,
        input: AnalyzeFailureInput,
    ) -> Result<AnalyzeFailureOutcome, FailureAnalysisError> {
        let AnalyzeFailureInput {
            execution_id: exec_id,
            user_id,
            apply_fix,
            auto_retry,
        } = input;

        // ── Fetch execution record ───────────────────────────────────────────
        let exec = match self.execution_repo.get_execution(exec_id, user_id).await {
            Ok(Some(e)) => e,
            Ok(None) => return Err(FailureAnalysisError::NotFound),
            Err(e) => {
                tracing::error!("analyze_execution_failure fetch failed: {}", e);
                return Err(FailureAnalysisError::ExecutionFetch(e));
            }
        };

        let status = exec.status.clone();
        let global_error = exec.error_message.clone();
        let workflow_id = exec.workflow_id;

        if status != "failed" && status != "cancelled" {
            return Err(FailureAnalysisError::NotAnalyzable { status });
        }

        // ── Build UUID→label map from workflow graph_json ────────────────────
        // SECURITY: use get_workflow_graph_for_user to enforce user_id constraint.
        let graph_str = self
            .execution_repo
            .get_workflow_graph_for_user(workflow_id, user_id)
            .await
            .ok()
            .flatten();
        let node_labels = build_node_display_label_map(graph_str);

        // ── Fetch node_failed events ─────────────────────────────────────────
        let all_events = match self.execution_repo.list_execution_events(exec_id).await {
            Ok(evs) => evs,
            Err(e) => {
                tracing::error!("analyze_execution_failure events fetch failed: {}", e);
                return Err(FailureAnalysisError::EventsFetch(e));
            }
        };
        let events: Vec<_> = all_events
            .into_iter()
            .filter(|e| e.event_type == "node_failed")
            .collect();

        // ── Build per-node diagnoses ─────────────────────────────────────────
        let mut failed_nodes: Vec<serde_json::Value> = Vec::new();
        for ev in &events {
            let raw_node_id = ev.node_id;
            let node_id_str = raw_node_id
                .map(|u| u.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let label = raw_node_id
                .and_then(|u| node_labels.get(&u).cloned())
                .unwrap_or_else(|| node_id_str.clone());
            let error_text = ev
                .log_message
                .as_deref()
                .unwrap_or("(no error message recorded)");

            let mut failed_node = build_failed_node_diagnosis(NodeDiagnosis {
                node_id: Some(node_id_str.as_str()),
                label: &label,
                remediation_label: &label,
                error_text,
                engine_error_class: ev.error_class.as_deref(),
                surface_reason_class: true,
            });
            let error_type = failed_node
                .get("error_type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            // Fuel-exhaustion advisor (2026-07-18 retrospective): the
            // generic playbook explains the fuel FORMULA but never told
            // the operator what number to SET — even though the platform
            // records actual consumption per successful run in
            // `execution_cost_rollup`. When history exists, attach it plus
            // a concrete recommendation: 1.5× the observed max (headroom
            // for payload growth), floored at 2× the median, rounded up
            // to 100K, clamped to the platform's [1M, 50M] fuel window.
            // Best-effort — a history-query error never degrades the
            // analysis itself.
            if error_type == "fuel_exhausted" {
                if let Ok(Some((runs, p50, max_seen))) = self
                    .execution_repo
                    .node_fuel_history(workflow_id, &label, user_id, 30)
                    .await
                {
                    let raw = ((max_seen as f64) * 1.5).max((p50 as f64) * 2.0) as i64;
                    let recommended = ((raw + 99_999) / 100_000) * 100_000;
                    let recommended = recommended.clamp(1_000_000, 50_000_000);
                    if let Some(obj) = failed_node.as_object_mut() {
                        obj.insert(
                            "fuel_history".to_string(),
                            serde_json::json!({
                                "successful_runs_30d": runs,
                                "p50_fuel": p50,
                                "max_fuel_observed": max_seen,
                                "recommended_max_fuel": recommended,
                                "note": format!(
                                    "Successful runs of '{label}' consumed up to {max_seen} fuel \
                                     (median {p50}) in the last 30 days. Set max_fuel to \
                                     ~{recommended} via update_node_config (node-level, wins over \
                                     the module default) or hot_update_module with fuel_budget."
                                ),
                            }),
                        );
                    }
                }
            }
            failed_nodes.push(failed_node);
        }

        // If no failed node events but execution failed (e.g. workflow-level error), use global error
        if failed_nodes.is_empty() {
            let error_text = global_error
                .as_deref()
                .unwrap_or("(no error details available)");
            failed_nodes.push(build_failed_node_diagnosis(NodeDiagnosis {
                node_id: None,
                label: "workflow-level",
                // The pre-extraction handler passed "workflow" here while
                // labelling the entry "workflow-level"; the two differ and the
                // difference is preserved verbatim.
                remediation_label: "workflow",
                error_text,
                engine_error_class: None,
                // Preserved: the workflow-level entry has never carried a
                // `reason_class` field. Surfacing one here would be an
                // additive shape change, and this change is not about that.
                surface_reason_class: false,
            }));
        }

        // Find first config_error node with an extractable field
        // Capture (node_id_uuid_str, node_label, field) — node_label is the reliable match key
        // because execution_events.node_id is a SHA256-derived UUID, not the graph node string id.
        let apply_fix_candidate = failed_nodes.iter().find_map(|n| {
            if n.get("error_type").and_then(|v| v.as_str()) == Some("config_error") {
                let raw = n.get("raw_error").and_then(|v| v.as_str()).unwrap_or("");
                let node_id = json_optional_string(n, "node_id");
                let node_label = json_optional_string(n, "label");
                if let Some(field) = extract_config_field(raw) {
                    return Some((node_id, node_label, field));
                }
            }
            None
        });

        let apply_fix_available = apply_fix_candidate.is_some();
        let mut fix_result: Option<serde_json::Value> = None;

        if apply_fix && apply_fix_available {
            if let Some((failed_node_id_opt, failed_node_label, field_name)) = &apply_fix_candidate
            {
                // Load graph_json (user-scoped)
                let graph_json_str = self
                    .execution_repo
                    .get_workflow_graph_for_user(workflow_id, user_id)
                    .await
                    .ok()
                    .flatten();

                if let Some(graph_json_str) = graph_json_str {
                    let mut graph: serde_json::Value = serde_json::from_str(&graph_json_str)
                        .unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

                    // Match by label (reliable) or fallback to UUID id string.
                    // execution_events.node_id is a SHA256-derived UUID; graph nodes use string ids
                    // like "node-1". The label is resolved via node_labels map and is the safe bridge.
                    let mut patched = false;
                    if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
                        for node in nodes.iter_mut() {
                            let nid = node.get("id").and_then(|v| v.as_str()).unwrap_or("");
                            let nlabel = node
                                .get("data")
                                .and_then(|d| d.get("label"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let label_match = failed_node_label
                                .as_deref()
                                .map(|l| l == nlabel)
                                .unwrap_or(false);
                            let id_match = failed_node_id_opt
                                .as_deref()
                                .map(|fid| fid == nid)
                                .unwrap_or(false);
                            if label_match || id_match {
                                if let Some(data) = node.get_mut("data") {
                                    // Set to empty string as a placeholder — user must still fill the value
                                    if data.get(field_name).is_none() || data[field_name].is_null()
                                    {
                                        data[field_name] = serde_json::json!("");
                                        patched = true;
                                    }
                                }
                                break;
                            }
                        }
                    }

                    let patched_node_display = failed_node_label
                        .as_deref()
                        .or(failed_node_id_opt.as_deref())
                        .unwrap_or("unknown");

                    if patched {
                        let updated_json = graph.to_string();
                        // MCP-1227 (2026-05-18): mirror the MCP-1226 chokepoint
                        // for this auto-fix write path. `analyze_execution_failure`
                        // can only stamp a single field with `""` (no caller-
                        // injected number that could violate caps), so the
                        // only way validation fails is if the legacy graph
                        // already has over-cap timeouts/retries. Surface that
                        // as `fix_applied: false` with the validator's
                        // pointer at the offending field — operator must
                        // hand-edit the legacy values before the auto-fix
                        // can land. Sibling defense-in-depth posture to
                        // `rollback_workflow` (versions.rs).
                        if let Err(cap_msg) =
                            talos_workflow_types::validate_graph_timeouts(&updated_json)
                        {
                            fix_result = Some(serde_json::json!({
                                "fix_applied": false,
                                "error": format!(
                                    "Existing workflow graph violates per-node / per-loop / per-retry caps; auto-fix refused. Edit the offending node by hand. Detail: {}",
                                    cap_msg
                                ),
                            }));
                        } else {
                            let db_result = self
                                .execution_repo
                                .update_workflow_graph(workflow_id, user_id, &updated_json)
                                .await;
                            // MCP-882 (2026-05-14): log the underlying error
                            // before collapsing to the generic "Failed to save
                            // patched graph" response. Pre-fix `db_result.is_ok()`
                            // branched on bool without logging the sqlx error,
                            // so an operator running diagnose_and_fix_node_failure
                            // saw "fix_applied: false" with no signal whether
                            // the failure was a permission issue, FK violation,
                            // write timeout, or graph-JSON shape rejection.
                            // Operator-facing message stays generic; server log
                            // distinguishes the cause.
                            match db_result {
                                Ok(_) => {
                                    fix_result = Some(serde_json::json!({
                                        "fix_applied": true,
                                        "patched_node": patched_node_display,
                                        "patched_field": field_name,
                                        "retry_with_execution_id": exec_id.to_string(),
                                        "note": "Field initialized to empty string — call update_node_config to set the correct value, then retry."
                                    }));
                                }
                                Err(e) => {
                                    tracing::error!(
                                        workflow_id = %workflow_id,
                                        user_id = %user_id,
                                        error = %e,
                                        "handle_analyze_execution_failure: update_workflow_graph failed during auto-fix"
                                    );
                                    fix_result = Some(serde_json::json!({
                                        "fix_applied": false,
                                        "error": "Failed to save patched graph"
                                    }));
                                }
                            }
                        }
                    } else {
                        fix_result = Some(serde_json::json!({
                            "fix_applied": false,
                            "note": format!("Node '{}' or field '{}' not found in current graph", patched_node_display, field_name)
                        }));
                    }
                }
            }
        }

        // If auto_retry=true and fix was applied, spawn a background retry
        let auto_retry_triggered = auto_retry
            && fix_result
                .as_ref()
                .and_then(|f| f.get("fix_applied"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

        if auto_retry_triggered {
            tracing::info!(execution_id = %exec_id, "analyze_execution_failure: auto_retry requested after fix_applied");
        }

        // Auth-error auto-fix: when apply_fix=true and the primary failure is
        // auth_error, extract the secret name and surface it on the
        // `auth_fix_suggestion` payload so the operator knows which row to
        // touch. Pre-MCP-1201 this also pre-filled a `rotate_secret` MCP call;
        // post-MCP-1201 MCP is read-only for secrets, so the rotation happens
        // in the dashboard (Settings → Secrets) — the suggestion just names
        // the secret + describes the action.
        let auth_fix_suggestion: Option<serde_json::Value> = if apply_fix {
            failed_nodes.iter().find_map(|n| {
                let err_type = n.get("error_type").and_then(|v| v.as_str()).unwrap_or("");
                if err_type == "auth_error" || err_type == "missing_secret" {
                    let raw = n.get("raw_error").and_then(|v| v.as_str()).unwrap_or("");
                    let secret_name = extract_secret_name_from_auth_error(raw);
                    let is_missing = err_type == "missing_secret";
                    // MCP-1201 (2026-05-17): secret writes moved exclusively
                    // to the GraphQL surface (require_2fa + SecretsWrite).
                    // The auth-fix suggestion no longer carries an MCP
                    // `tool` + `prefilled_args` because no MCP tool can
                    // execute the fix. Returning the extracted secret name
                    // and a clear "do this in the dashboard" note keeps the
                    // diagnostic value (caller knows which secret to
                    // touch) while routing the actual mutation through the
                    // 2FA-gated path.
                    Some(serde_json::json!({
                        "fix_type": if is_missing { "provision_secret" } else { "rotate_secret" },
                        "tool": null,
                        "extracted_secret_name": secret_name,
                        "note": if let Some(ref sn) = secret_name {
                            if is_missing {
                                format!(
                                    "Secret '{}' was not found in the vault. Provision it in the dashboard (Settings → Secrets) using the key_path extracted from the error message — secret writes require 2FA and aren't available through MCP.",
                                    sn
                                )
                            } else {
                                format!(
                                    "Auth error detected for secret '{}'. Generate a fresh credential and rotate it in the dashboard (Settings → Secrets) — secret writes require 2FA and aren't available through MCP.",
                                    sn
                                )
                            }
                        } else {
                            "Credential reference found in error. Identify the secret name from raw_error and provision it in the dashboard (Settings → Secrets) — secret writes require 2FA and aren't available through MCP.".to_string()
                        }
                    }))
                } else {
                    None
                }
            })
        } else {
            None
        };

        let effective_fix_available = apply_fix_available || auth_fix_suggestion.is_some();
        let mut result = serde_json::json!({
            "execution_id": exec_id.to_string(),
            "workflow_id": workflow_id.to_string(),
            "status": status,
            "failed_node_count": failed_nodes.len(),
            "failed_nodes": failed_nodes,
            "global_error": global_error,
            "apply_fix_available": effective_fix_available,
            "tip": format!(
                "After applying fixes, call retry_execution with execution_id={}.",
                exec_id
            ),
        });

        if let Some(fix) = fix_result {
            result["fix_result"] = fix;
        }
        if let Some(auth_fix) = auth_fix_suggestion {
            result["auth_fix_suggestion"] = auth_fix;
        }
        if auto_retry_triggered {
            result["auto_retry_triggered"] = serde_json::json!(true);
            result["auto_retry_note"] = serde_json::json!(
                "Background retry has been enqueued. Call retry_execution explicitly to get the new execution_id."
            );
        }

        Ok(AnalyzeFailureOutcome { report: result })
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Error strings locked verbatim (r304 discipline) ────────────────────

    #[test]
    fn error_strings_locked_verbatim() {
        assert_eq!(
            FailureAnalysisError::NotFound.user_facing_message(),
            "Execution not found or access denied"
        );
        assert_eq!(
            FailureAnalysisError::NotAnalyzable {
                status: "running".to_string()
            }
            .user_facing_message(),
            "Execution status is 'running' — only failed or cancelled executions can be analyzed."
        );
        assert_eq!(
            FailureAnalysisError::ExecutionFetch(anyhow::anyhow!(
                "connection refused to db host 10.0.0.3"
            ))
            .user_facing_message(),
            "Database error fetching execution"
        );
        assert_eq!(
            FailureAnalysisError::EventsFetch(anyhow::anyhow!(
                "relation execution_events does not exist"
            ))
            .user_facing_message(),
            "Database error fetching execution events"
        );
    }

    #[test]
    fn internal_errors_never_leak_source_detail() {
        // The #[source] chain must not render through the user-facing
        // message — a sqlx error naming schema objects stays server-side.
        let err = FailureAnalysisError::ExecutionFetch(anyhow::anyhow!(
            "SELECT id FROM workflow_executions failed: column does_not_exist"
        ));
        let msg = err.user_facing_message();
        assert!(!msg.contains("SELECT"));
        assert!(!msg.contains("workflow_executions"));
        assert!(!msg.contains("column"));
    }

    #[test]
    fn jsonrpc_codes_stable() {
        assert_eq!(FailureAnalysisError::NotFound.jsonrpc_code(), -32000);
        assert_eq!(
            FailureAnalysisError::NotAnalyzable {
                status: "completed".into()
            }
            .jsonrpc_code(),
            -32000
        );
        assert_eq!(
            FailureAnalysisError::ExecutionFetch(anyhow::anyhow!("x")).jsonrpc_code(),
            -32000
        );
        assert_eq!(
            FailureAnalysisError::EventsFetch(anyhow::anyhow!("x")).jsonrpc_code(),
            -32000
        );
    }

    // ── The fall-through must not assert a cause ────────────────────────────

    /// The exact `execution_events.log_message` of a live failure, and the
    /// answer it used to get.
    ///
    /// Observed 2026-09-04. Nothing was wrong with the module: this is the
    /// platform's own per-host circuit breaker deliberately refusing to call
    /// an upstream that had been failing, which is correct protective
    /// behaviour and self-healed within the hour. The report named
    /// `runtime_error` / "An unexpected runtime error occurred inside the
    /// module" and prescribed a four-step investigation INTO the module,
    /// ending at `run_sandbox`.
    ///
    /// The string carries no `[reason_class=…]` marker — asserted below,
    /// because that absence is the whole reason the marked form was already
    /// handled and this one was not.
    #[test]
    fn the_observed_circuit_breaker_trip_is_not_blamed_on_the_module() {
        const OBSERVED: &str = "Job failed (retry_condition not met): execution failure: \
circuit open for host gmail.googleapis.com: cooling down after repeated failures — \
skipping retries until the host recovers";

        assert!(
            !OBSERVED.contains(talos_reason_class::MARKER_KEY),
            "the observed message now carries a marker — if the worker started \
             stamping the retry-gate fast-fail, the hoisted marker arm handles it \
             and this unmarked arm is redundant"
        );

        let (bucket, description) = classify_error(OBSERVED);
        assert_eq!(bucket, "circuit_open");
        assert!(
            !description.contains("inside the module"),
            "the platform's own protective refusal is reported as a module fault: \
             {description}"
        );
        assert!(
            description.contains("Nothing is misconfigured"),
            "the description must say the module is not at fault: {description}"
        );

        // And the playbook must not send the operator to reproduce a module
        // that is fine.
        let steps = remediation_steps(bucket, "gmail_work");
        let first_tool = steps
            .first()
            .and_then(|s| s.get("tool"))
            .and_then(|t| t.as_str());
        assert_eq!(first_tool, Some("tail_worker_logs"));
    }

    /// The MARKED and UNMARKED spellings of ONE refusal must give ONE answer.
    ///
    /// The breaker fires on two paths. Inside the host HTTP function it
    /// produces a guest `networkerror` with `[reason_class=circuit-open]`
    /// appended; in the retry gate
    /// (`talos_worker_runtime::runtime::circuit_open_message`) it produces
    /// plain prose with no marker. Both are the same refusal for the same
    /// reason and deserve the same playbook — the marked one got it and the
    /// unmarked one got `runtime_error`.
    #[test]
    fn both_spellings_of_the_breaker_refusal_agree() {
        let marked = "Job failed after 3 attempts: execution failure: Component returned \
error: list fetch: Error { code: 2, name: \"networkerror\", message: \"\" } \
[reason_class=circuit-open]";
        let unmarked = "Job failed after 1 attempts: execution failure: circuit open for \
host www.googleapis.com: cooling down after repeated failures — skipping retries until \
the host recovers";
        assert_eq!(
            classify_error(marked),
            classify_error(unmarked),
            "the same refusal answers differently depending on which breaker path fired"
        );
    }

    /// The breaker hoist has to sit ABOVE the prose chain, not below it.
    ///
    /// The fast-fail message can carry the last underlying error, and that
    /// tail contains transient tokens the chain matches first — so a call
    /// that was never attempted would be reported as a live network failure
    /// or a timeout, with a playbook that says to retry. This is the same
    /// reason `talos_retry_intelligence::classify_error` hoists its own
    /// circuit-open arm above everything.
    #[test]
    fn the_breaker_hoist_beats_a_transient_tail() {
        for tail in [
            "circuit open for host api.example.com (last error: connection refused)",
            "circuit open for host api.example.com (last error: request timed out)",
        ] {
            assert_eq!(
                classify_error(tail).0,
                "circuit_open",
                "a transient token in the fast-fail's tail outranked the refusal itself"
            );
        }
    }

    /// AN UNRECOGNISED MESSAGE MUST NOT CLAIM TO KNOW WHAT HAPPENED.
    ///
    /// This is the durable half of the fix and the reason coverage alone was
    /// not enough: a pattern cascade always has a fall-through, so whatever
    /// the next unrecognised cause turns out to be, it lands here. The old
    /// answer stated a determinate cause AND a location — "An unexpected
    /// runtime error occurred inside the module" — for input the classifier
    /// had explicitly failed to match, while the remediation prose for the
    /// same bucket already said "the error text matched no specific gate"
    /// and the tool description already said to treat it as "unexplained".
    /// The two machine-readable fields were the last ones still asserting.
    #[test]
    fn the_fall_through_makes_no_claim_about_where_the_fault_is() {
        let (bucket, description) = classify_error("something nobody has ever seen before");
        assert_eq!(bucket, "unclassified");
        assert!(
            !description.contains("An unexpected runtime error occurred inside the module"),
            "the fall-through still asserts a cause and a location: {description}"
        );
        assert!(
            description.contains("does NOT know what went wrong"),
            "the fall-through must say the cause is unknown: {description}"
        );
        assert!(
            description.contains("NOT established that the fault is in the module"),
            "the fall-through must decline to locate the fault: {description}"
        );
    }

    /// The fall-through PLAYBOOK must not prescribe reproducing the module.
    ///
    /// `run_sandbox` is not wrong to offer — it is wrong to offer
    /// unconditionally, because the bucket's own meaning is that nobody knows
    /// whether the module is involved. Of the 20 `node_failed` events that
    /// reached this arm on the deployed stack in the 30 days to 2026-09-04,
    /// 19 were platform-side and reproducing the module would have shown it
    /// working.
    #[test]
    fn the_fall_through_playbook_does_not_prescribe_reproducing_the_module() {
        let steps = remediation_steps("unclassified", "some_node");
        let sandbox = steps
            .iter()
            .find(|s| s.get("tool").and_then(|t| t.as_str()) == Some("run_sandbox"))
            .expect("the fall-through playbook still offers run_sandbox");
        let text = sandbox
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or_default();
        assert!(
            text.contains("ONLY IF"),
            "the fall-through prescribes reproducing the module unconditionally: {text}"
        );
        assert!(
            text.contains("NOT a finding that the module is at fault"),
            "the fall-through's sandbox step must state that the bucket is not a \
             diagnosis: {text}"
        );
    }

    /// The bucket NAME is part of the claim, not just its description.
    ///
    /// `error_type` is the machine-readable field an agent branches on, and
    /// `runtime_error` names a determinate cause ("a runtime error") in the
    /// same breath as the description named a location. Fixing only the prose
    /// would have left the field an agent reads still asserting while the
    /// field a human reads told the truth — the same split, one level down.
    #[test]
    fn the_fall_through_bucket_name_names_no_cause() {
        let (bucket, _) = classify_error("something nobody has ever seen before");
        for asserted in ["runtime", "module", "error"] {
            assert!(
                !bucket.contains(asserted),
                "the fall-through bucket name `{bucket}` still names a cause"
            );
        }
    }

    /// THE REPORT FIELD, not just the classifier's return value.
    ///
    /// Drives the production builder that `analyze` calls for every failed
    /// node and reads what the operator actually receives. Written because a
    /// call-site mutation — classify correctly, then write a hard-coded
    /// `("runtime_error", "An unexpected runtime error occurred inside the
    /// module.")` into the report — was MEASURED to leave every other test in
    /// this crate green, which is the whole defect restored under a green
    /// suite.
    #[test]
    fn the_report_field_an_operator_reads_does_not_blame_the_module() {
        const OBSERVED: &str = "Job failed (retry_condition not met): execution failure: \
circuit open for host gmail.googleapis.com: cooling down after repeated failures — \
skipping retries until the host recovers";

        let node = build_failed_node_diagnosis(NodeDiagnosis {
            node_id: Some("11111111-1111-1111-1111-111111111111"),
            label: "gmail_work",
            remediation_label: "gmail_work",
            error_text: OBSERVED,
            engine_error_class: Some("non-transient"),
            surface_reason_class: true,
        });

        assert_eq!(
            node.get("error_type").and_then(|v| v.as_str()),
            Some("circuit_open")
        );
        let desc = node
            .get("error_description")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert!(
            !desc.contains("inside the module"),
            "the report blames the module for the platform's own refusal: {desc}"
        );
        // Preserved fields the report has always carried.
        assert_eq!(
            node.get("label").and_then(|v| v.as_str()),
            Some("gmail_work")
        );
        assert_eq!(
            node.get("raw_error").and_then(|v| v.as_str()),
            Some(OBSERVED)
        );
        assert_eq!(
            node.get("engine_error_class").and_then(|v| v.as_str()),
            Some("non-transient")
        );
        // No marker on this message, so no fabricated `reason_class`.
        assert!(node.get("reason_class").is_none());
    }

    /// The workflow-level entry keeps its pre-extraction shape exactly.
    ///
    /// Two details are easy to lose in a refactor and both are load-bearing:
    /// the entry labels itself `workflow-level` but interpolates `workflow`
    /// into its remediation steps, and it has never carried a `reason_class`
    /// field even when the global error text has a marker.
    #[test]
    fn the_workflow_level_entry_keeps_its_shape() {
        let node = build_failed_node_diagnosis(NodeDiagnosis {
            node_id: None,
            label: "workflow-level",
            remediation_label: "workflow",
            error_text: "Scheduled workflow failed: something odd [reason_class=dns]",
            engine_error_class: None,
            surface_reason_class: false,
        });
        assert!(node.get("node_id").is_some_and(serde_json::Value::is_null));
        assert_eq!(
            node.get("label").and_then(|v| v.as_str()),
            Some("workflow-level")
        );
        assert!(node.get("reason_class").is_none());
        assert!(node.get("engine_error_class").is_none());
        let steps = serde_json::to_string(node.get("remediation_steps").unwrap()).unwrap();
        assert!(
            steps.contains("'workflow'"),
            "the workflow-level entry stopped interpolating `workflow`: {steps}"
        );
    }

    // ── classify_error buckets ──────────────────────────────────────────────

    /// A HOST-POLICY DENIAL IS INVISIBLE TO `classify_error`, AND THAT IS WHY
    /// THE FALL-THROUGH PLAYBOOK MUST NAME `tail_worker_logs`.
    ///
    /// The worker refuses the call and records the reason itself —
    /// `[host:insecure-scheme] http-fetch denied by policy 'insecure-scheme'
    /// (target: http host.docker.internal)`, WARN, into `module_execution_logs`.
    /// What reaches the ENGINE, and therefore what `classify_error` is handed,
    /// is only the module's downstream error after the refusal. The string
    /// below is the verbatim `execution_events.log_message` of a real failure
    /// (workflow_execution 43b78079-d0a0-4aff-83f1-e3e80dc7195a, 2026-09-01):
    /// it names no host, no policy, and no denial, so it matches none of the
    /// specific gates — including `host_not_allowed` — and lands in the
    /// fall-through bucket.
    ///
    /// This is a TRIPWIRE, not a pin on a value I chose. If a future gate
    /// starts catching this shape, this test fails and tells you the real
    /// requirement: the `tail_worker_logs` step must MOVE to whichever bucket
    /// now claims it, because a classifier reading only the downstream error
    /// can never identify a policy denial on its own.
    #[test]
    fn a_host_policy_denial_reaches_the_classifier_only_as_its_downstream_error() {
        const OBSERVED: &str = "Job failed after 1 attempts: execution failure: \
Component returned error: HTTP request failed: Error { code: 0, name: \"invalidurl\", message: \"\" }";

        let (bucket, _) = classify_error(OBSERVED);
        assert_eq!(
            bucket, "unclassified",
            "the observed host-denial error now classifies as `{bucket}`; move the \
             tail_worker_logs remediation step into that bucket's arm"
        );

        // The refusal itself is not in this string in any form — that is the
        // whole defect, stated as an assertion rather than as prose.
        let lower = OBSERVED.to_lowercase();
        for absent in ["denied", "policy", "insecure-scheme", "host:", "forbidden"] {
            assert!(
                !lower.contains(absent),
                "the downstream error unexpectedly carries `{absent}` — if the worker \
                 now propagates the refusal reason, the classifier can gate on it directly"
            );
        }
    }

    /// Both buckets an operator reaches on a policy denial must name the ONLY
    /// tool that returns the worker's own lines.
    ///
    /// `host_not_allowed` is the bucket that is explicitly about host gating;
    /// the fall-through is where a denial actually lands (see the test above).
    /// Before this was enforced, neither named `tail_worker_logs` — it was
    /// named in ZERO operator-facing hints anywhere in the workspace — and the
    /// fall-through's step 1 sent the operator to `get_execution_logs`, which
    /// reads `execution_events` and structurally cannot contain the line.
    #[test]
    fn the_playbooks_for_a_policy_denial_name_the_tool_that_shows_it() {
        for bucket in ["host_not_allowed", "unclassified", "an_unmatched_bucket"] {
            let steps = remediation_steps(bucket, "some_node");
            let names_it = steps
                .iter()
                .any(|s| s.get("tool").and_then(|t| t.as_str()) == Some("tail_worker_logs"));
            assert!(
                names_it,
                "remediation_steps({bucket}) does not name tail_worker_logs — a host-policy \
                 denial is written by the worker into module_execution_logs, which no other \
                 surface reachable from a workflow-execution id reads, so this playbook cannot \
                 explain the failure it is for"
            );
        }
    }

    #[test]
    fn classify_error_buckets() {
        assert_eq!(
            classify_error("OUTPUT_SCHEMA enforcement fired: required keys missing").0,
            "output_schema_violation"
        );
        assert_eq!(
            classify_error("ForbiddenHost: example.com").0,
            "host_not_allowed"
        );
        assert_eq!(
            classify_error("compilation failed at line 3").0,
            "module_compile_error"
        );
        assert_eq!(
            classify_error("invalid type: expected struct").0,
            "json_parse"
        );
        assert_eq!(
            classify_error("secret not found in vault").0,
            "missing_secret"
        );
        assert_eq!(classify_error("429 Too Many Requests").0, "rate_limit");
        assert_eq!(
            classify_error("out of fuel after 5M ops").0,
            "fuel_exhausted"
        );
        assert_eq!(classify_error("wasm trap: unreachable").0, "wasm_trap");
        assert_eq!(classify_error("deadline exceeded").0, "timeout");
        assert_eq!(classify_error("connection refused").0, "network_error");
        // NOTE: the module-runtime form "Missing 'X' in config" does NOT
        // hit the config_error bucket (classify_error has no "missing '"
        // gate — only extract_config_field does). Locked as-is: changing
        // the bucket would change which failures offer the auto-fix.
        assert_eq!(
            classify_error("Missing 'AUTH_HEADER' in config").0,
            "unclassified"
        );
        assert_eq!(
            classify_error("missing field 'AUTH_HEADER'").0,
            "config_error"
        );
        assert_eq!(classify_error("HTTP 401 invalid token").0, "http_401");
        assert_eq!(classify_error("403 Forbidden").0, "http_403");
        assert_eq!(classify_error("404 endpoint missing").0, "http_404");
        assert_eq!(classify_error("502 bad gateway").0, "http_5xx");
        assert_eq!(classify_error("Unauthorized").0, "auth_error");
        assert_eq!(
            classify_error("postgres pool exhausted").0,
            "database_error"
        );
        assert_eq!(classify_error("something inexplicable").0, "unclassified");
    }

    #[test]
    fn classify_error_descriptions_locked() {
        assert_eq!(
            classify_error("secret not found").1,
            "A required secret credential was not found in the vault."
        );
        assert_eq!(
            classify_error("something inexplicable").1,
            "The failure text matched no known cause, so this analysis does NOT know what went wrong — and in particular has NOT established that the fault is in the module. Platform-side causes arrive here as text this classifier does not recognise: a host-policy denial (recorded only in the worker's own log), a rejected or unreadable job result, a breaker or budget refusal from an older worker. Read raw_error and the worker's own lines before changing the module."
        );
        assert_eq!(
            classify_error("missing field 'X'").1,
            "A required configuration field is missing or invalid."
        );
    }

    #[test]
    fn classify_specificity_order_forbiddenhost_beats_403() {
        // "forbidden" appears in ForbiddenHost but the host gate is more
        // specific and must win (the http_403 arm explicitly excludes it).
        assert_eq!(classify_error("ForbiddenHost").0, "host_not_allowed");
    }

    // ── truncate_for_classify ───────────────────────────────────────────────

    #[test]
    fn truncate_respects_char_boundaries() {
        // Multi-byte char straddling the 4096 boundary must not panic.
        let mut s = "a".repeat(4095);
        s.push('é'); // 2-byte char at offset 4095..4097
        s.push_str(&"b".repeat(100));
        let t = truncate_for_classify(&s);
        assert!(t.len() <= 4096);
        assert!(t.is_char_boundary(t.len()));
    }

    #[test]
    fn truncate_noop_under_cap() {
        assert_eq!(truncate_for_classify("short"), "short");
    }

    #[test]
    fn classify_ignores_tokens_buried_past_cap() {
        let mut s = "x".repeat(5000);
        s.push_str("out of fuel");
        assert_eq!(classify_error(&s).0, "unclassified");
    }

    // ── extract_config_field ────────────────────────────────────────────────

    #[test]
    fn extract_config_field_patterns() {
        assert_eq!(
            extract_config_field("Missing 'AUTH_HEADER' in config"),
            Some("AUTH_HEADER".to_string())
        );
        assert_eq!(
            extract_config_field("missing field 'url'"),
            Some("url".to_string())
        );
        assert_eq!(
            extract_config_field("required field \"api_key\" absent"),
            Some("api_key".to_string())
        );
        assert_eq!(
            extract_config_field("invalid config key 'TIMEOUT'"),
            Some("TIMEOUT".to_string())
        );
        assert_eq!(extract_config_field("no recognizable pattern here"), None);
    }

    // ── extract_secret_name_from_auth_error ─────────────────────────────────

    #[test]
    fn extract_secret_name_patterns() {
        assert_eq!(
            extract_secret_name_from_auth_error("secret 'github/token' not found"),
            Some("github/token".to_string())
        );
        assert_eq!(
            extract_secret_name_from_auth_error("key 'anthropic/api_key' rejected"),
            Some("anthropic/api_key".to_string())
        );
        assert_eq!(
            extract_secret_name_from_auth_error("credential 'jira' expired"),
            Some("jira".to_string())
        );
        assert_eq!(extract_secret_name_from_auth_error("no names here"), None);
    }

    // ── remediation_steps shape ─────────────────────────────────────────────

    #[test]
    fn remediation_steps_known_buckets_nonempty() {
        for bucket in [
            "output_schema_violation",
            "host_not_allowed",
            "module_compile_error",
            "json_parse",
            "fuel_exhausted",
            "timeout",
            "http_401",
            "http_403",
            "http_404",
            "http_5xx",
            "missing_secret",
            "rate_limit",
            "wasm_trap",
            "network_error",
            "config_error",
            "auth_error",
            "database_error",
            "unclassified",
        ] {
            let steps = remediation_steps(bucket, "my-node");
            assert!(!steps.is_empty(), "bucket {bucket} has no steps");
            for (i, s) in steps.iter().enumerate() {
                assert_eq!(
                    s.get("step").and_then(|v| v.as_u64()),
                    Some(i as u64 + 1),
                    "bucket {bucket} step numbering broken"
                );
                assert!(s.get("description").is_some());
                assert!(s.get("action").is_some());
            }
        }
    }

    #[test]
    fn remediation_steps_interpolate_label() {
        let steps = remediation_steps("host_not_allowed", "fetch-node");
        let first = steps[0].get("description").unwrap().as_str().unwrap();
        assert!(first.contains("'fetch-node'"));
    }

    // ── build_node_display_label_map ────────────────────────────────────────

    #[test]
    fn label_map_uses_data_label_with_id_fallback() {
        let graph = serde_json::json!({
            "nodes": [
                { "id": "node-1", "data": { "label": "Fetch Issues" } },
                { "id": "node-2", "data": {} }
            ],
            "edges": []
        });
        let map = build_node_display_label_map(Some(graph.to_string()));
        assert_eq!(map.len(), 2);
        assert!(map.values().any(|v| v == "Fetch Issues"));
        assert!(map.values().any(|v| v == "node-2"));
    }

    /// Pinned against `(graph_json node id, execution_events.node_id)` pairs
    /// read out of a LIVE events table (2026-08-28) — NOT against a
    /// test-local re-derivation, which would pass even if both the map and
    /// the copy drifted together. If this map ever stops keying on what the
    /// executor actually wrote, every label lookup in the failure analyser
    /// silently degrades to a raw UUID instead of erroring.
    #[test]
    fn label_map_keys_match_ids_observed_in_the_events_table() {
        for (graph_id, observed) in [
            ("fetch", "e7d3799e-cc09-f5cb-c446-aa0a79bb1fb9"),
            ("send", "27ce1d1b-f427-0020-e179-9f12e647f5cb"),
            ("verify_extract", "49aabc38-d51d-b8eb-b360-1ba13d54f45c"),
        ] {
            let graph = serde_json::json!({
                "nodes": [{ "id": graph_id, "data": { "label": "L" } }],
                "edges": []
            });
            let map = build_node_display_label_map(Some(graph.to_string()));
            let expected: Uuid = observed.parse().expect("pinned id parses");
            assert_eq!(
                map.get(&expected).map(String::as_str),
                Some("L"),
                "label map no longer keys on the node_id the executor wrote for \
                 graph node '{graph_id}' — label lookups will fall through to raw UUIDs"
            );
        }
    }

    /// A UUID-shaped graph node id is adopted verbatim, not hashed. No live
    /// workflow currently uses one (checked against the events table
    /// 2026-08-28), so this arm is pinned synthetically via the canonical
    /// function rather than against observed data.
    #[test]
    fn label_map_passes_uuid_shaped_ids_through_unhashed() {
        let explicit = "0f5f4a2c-1c3e-4a7d-9b2f-0c1d2e3f4a5b";
        let graph = serde_json::json!({
            "nodes": [{ "id": explicit, "data": { "label": "L" } }],
            "edges": []
        });
        let map = build_node_display_label_map(Some(graph.to_string()));
        let expected: Uuid = explicit.parse().expect("explicit id parses");
        assert_eq!(map.get(&expected).map(String::as_str), Some("L"));
    }

    #[test]
    fn label_map_empty_on_none_or_malformed() {
        assert!(build_node_display_label_map(None).is_empty());
        assert!(build_node_display_label_map(Some("not json".to_string())).is_empty());
    }

    // ── reason_class marker vocabulary ──────────────────────────────────────

    /// The ten WIT discriminant names an egress failure can carry, across all
    /// four surfaces. `wit_http` renders unhyphenated (`forbiddenhost`);
    /// `wit_http_stream` renders HYPHENATED (`forbidden-host`) — wit-bindgen
    /// emits the case name verbatim — which is why both spellings are here and
    /// why they classify differently below.
    const WIT_NAMES: &[&str] = &[
        "networkerror",
        "invalidurl",
        "forbiddenhost",
        "timeout",
        "queryerror",
        "sendfailed",
        "forbidden-host",
        "invalid-url",
        "connection-failed",
        "rate-limited",
    ];

    fn guest_error(wit: &str) -> String {
        format!(
            r#"Component returned error: fetch: Error {{ code: 2, name: "{wit}", message: "" }}"#
        )
    }

    /// **(b) NOTHING UNMARKED MOVES.**
    ///
    /// The marker arm is hoisted above every prose gate, so the one thing this
    /// change must not do is disturb a message that carries no marker — and
    /// every row already on disk is such a message. Pinned as LITERALS rather
    /// than derived: a behavioural test written against the new code cannot
    /// catch a drift that moved the classifier and the expectation together.
    ///
    /// These ten values were MEASURED against the pre-change classifier, not
    /// chosen. Two are worth reading twice, because they are pre-existing
    /// defects this change deliberately does not touch on the unmarked path:
    /// `forbidden-host` (the http-stream spelling) answers `http_403` — "the
    /// credential lacks the required scope" for what is actually a host
    /// denial — and `connection-failed` answers `unclassified` because the
    /// chain's needle is `connection failed` with a SPACE.
    #[test]
    fn unmarked_messages_classify_exactly_as_before() {
        let expected: &[(&str, &str)] = &[
            ("networkerror", "network_error"),
            ("invalidurl", "unclassified"),
            ("forbiddenhost", "host_not_allowed"),
            ("timeout", "timeout"),
            ("queryerror", "unclassified"),
            ("sendfailed", "unclassified"),
            ("forbidden-host", "http_403"),
            ("invalid-url", "unclassified"),
            ("connection-failed", "unclassified"),
            ("rate-limited", "unclassified"),
        ];
        assert_eq!(expected.len(), WIT_NAMES.len());
        for (wit, bucket) in expected {
            assert_eq!(
                classify_error(&guest_error(wit)).0,
                *bucket,
                "UNMARKED {wit:?} moved bucket — the marker arm must be inert \
                 on a message that carries no marker"
            );
        }
    }

    /// **(a) EVERY TOKEN LANDS ON A PLAYBOOK THAT COULD RESOLVE IT.**
    ///
    /// Drives the real `classify_error` over the real closed set — the list
    /// comes from `talos_reason_class::ALL`, not from a copy here, so a token
    /// added upstream fails `every_reason_class_token_is_covered` below rather
    /// than silently skipping this table.
    ///
    /// The expectations are written per TOKEN, not per family, because the
    /// mapping from cause to remediation is the claim under test and deriving
    /// it from the same `family()` call the production path uses would make
    /// the assertion vacuous.
    #[test]
    fn every_reason_class_token_maps_to_its_remediation_bucket() {
        let cases: &[(&str, &str)] = &[
            // Transport — reuses the existing bucket.
            ("dns", "network_error"),
            ("tls", "network_error"),
            ("connect-refused", "network_error"),
            ("connect-failed", "network_error"),
            ("send-failed", "network_error"),
            ("response-stream", "network_error"),
            // Reuse: the existing playbooks are already right.
            ("timeout", "timeout"),
            ("secret-lookup", "missing_secret"),
            ("no-allowlist", "host_not_allowed"),
            ("allowed-hosts", "host_not_allowed"),
            // New buckets — one per remediation.
            ("circuit-open", "circuit_open"),
            ("cancelled", "execution_cancelled"),
            ("response-too-large", "response_too_large"),
            ("header-cap", "response_too_large"),
            ("request-header-cap", "request_too_large"),
            ("request-body-cap", "request_too_large"),
            ("url-too-long", "invalid_url"),
            ("url-parse", "invalid_url"),
            ("insecure-scheme", "insecure_scheme"),
            ("capability-world", "capability_world_denied"),
            ("private-ip", "ssrf_blocked"),
            ("tier1-egress", "egress_tier_denied"),
            ("tier1-llm-egress", "egress_tier_denied"),
            ("tier1-public-ip-egress", "egress_tier_denied"),
            ("write-ceiling", "write_ceiling_denied"),
            ("write-ceiling-strict-egress", "write_ceiling_denied"),
            ("method-allowlist", "method_not_allowed"),
            ("execution-rate-limit", "egress_budget_exceeded"),
            ("per-host-rate-limit", "egress_budget_exceeded"),
            ("sse-stream-cap", "egress_budget_exceeded"),
            ("graphql-introspection", "introspection_denied"),
        ];

        for (token, bucket) in cases {
            // Asserted against EVERY discriminant it could ride on, not just
            // the one its own site returns: the marker is authoritative
            // wherever it appears, and a future emitting site that pairs
            // differently must not change the answer.
            for wit in WIT_NAMES {
                let marked = format!("{} [reason_class={token}]", guest_error(wit));
                assert_eq!(
                    classify_error(&marked).0,
                    *bucket,
                    "[reason_class={token}] on a {wit:?} message classified wrongly"
                );
            }
            // And a non-empty description, since the description is what the
            // operator actually reads.
            let marked = format!("{} [reason_class={token}]", guest_error("networkerror"));
            assert!(!classify_error(&marked).1.is_empty());
        }
    }

    /// The table above must cover the producer's closed set — TOTALITY, so a
    /// token added upstream cannot slip through untested.
    #[test]
    fn every_reason_class_token_is_covered_by_a_family() {
        for token in talos_reason_class::ALL {
            assert!(
                talos_reason_class::family(token).is_some(),
                "token {token:?} has no Family, so classify_error falls through \
                 to its pre-marker bucket for it"
            );
        }
        assert_eq!(talos_reason_class::ALL.len(), 31);
    }

    /// A token this build has never heard of — an older controller reading a
    /// newer worker — must fall through to the pre-marker chain, never to a
    /// guessed bucket.
    #[test]
    fn an_unknown_token_falls_through_instead_of_guessing() {
        let msg = format!(
            "{} [reason_class=from-the-future]",
            guest_error("forbiddenhost")
        );
        assert_eq!(classify_error(&msg).0, "host_not_allowed");
        let msg = format!(
            "{} [reason_class=from-the-future]",
            guest_error("invalidurl")
        );
        assert_eq!(classify_error(&msg).0, "unclassified");
    }

    /// The 4 KiB cap and the marker's position interact, and the interaction
    /// is in the SAFE direction: the worker APPENDS the marker, so on an
    /// over-cap message it is truncated away and the message classifies
    /// exactly as it did before markers existed. Asserted rather than
    /// described, because "we thought about it" is not a guarantee.
    ///
    /// Left as-is deliberately: the cap bounds an O(N) scan over a
    /// guest-influenced string, and a policy denial — the case the marker
    /// exists for — is short by construction, since the request never left
    /// the host and there is no response body to inflate the message.
    #[test]
    fn a_marker_past_the_cap_reverts_to_the_pre_marker_bucket() {
        let mut s = guest_error("invalidurl");
        s.push_str(&"x".repeat(5000));
        s.push_str(" [reason_class=insecure-scheme]");
        assert_eq!(
            classify_error(&s).0,
            "unclassified",
            "an over-cap marker must be invisible, not half-read"
        );
        // Under the cap, the same message is explained.
        let short = format!(
            "{} [reason_class=insecure-scheme]",
            guest_error("invalidurl")
        );
        assert_eq!(classify_error(&short).0, "insecure_scheme");
    }

    /// The bucket a live denial actually produces, end to end.
    ///
    /// The string is the shape observed on the deployed stack after #714/#717:
    /// the same `invalidurl` body as the pre-marker capture pinned by
    /// `a_host_policy_denial_reaches_the_classifier_only_as_its_downstream_error`
    /// above, plus the marker the worker now appends. That test asserts the
    /// UNMARKED form still answers `unclassified`; this one asserts the
    /// MARKED form no longer does — the two together are the whole change.
    #[test]
    fn the_observed_live_denial_is_now_explained() {
        const OBSERVED: &str = "Job failed after 1 attempts: execution failure: \
Component returned error: HTTP request failed: Error { code: 0, name: \"invalidurl\", message: \"\" } \
[reason_class=insecure-scheme]";
        let (bucket, description) = classify_error(OBSERVED);
        assert_eq!(bucket, "insecure_scheme");
        assert!(
            description.contains("SECURITY gate"),
            "the description must say this is not an allowlist miss: {description}"
        );
        // And the playbook must not PRESCRIBE widening allowed_hosts. It may
        // — and does — mention it in order to rule it out, which is a
        // different act and the more useful one for an operator arriving
        // from the old advice.
        let steps = remediation_steps(bucket, "fetch-node");
        let all_text = serde_json::to_string(&steps).unwrap();
        assert!(
            !all_text.contains("update_module_hosts"),
            "the insecure_scheme playbook prescribes update_module_hosts, which cannot fix it"
        );
        assert!(
            all_text.contains("widening allowed_hosts will not lift it"),
            "the insecure_scheme playbook must explicitly rule out the advice this \
             bucket used to be given: {all_text}"
        );
    }

    /// Every playbook reachable from a host-stamped POLICY denial must name
    /// `tail_worker_logs`.
    ///
    /// Not decoration: the marker carries the family, but the worker's own
    /// `[host:<policy>] … (target: …)` line is the only place the TARGET and
    /// the precise variant appear — `private-ip` stands for an open SSRF
    /// family and `graphql-introspection` for a two-member one, both collapsed
    /// on the wire so the token set stays closed.
    ///
    /// `missing_secret` and `response_too_large`'s siblings are excluded by
    /// name below where their existing playbook is already the right one and
    /// does not need the worker log.
    #[test]
    fn every_denial_playbook_names_the_tool_that_shows_the_target() {
        for bucket in [
            "host_not_allowed",
            "insecure_scheme",
            "capability_world_denied",
            "ssrf_blocked",
            "egress_tier_denied",
            "write_ceiling_denied",
            "method_not_allowed",
            "egress_budget_exceeded",
            "introspection_denied",
            "request_too_large",
            "response_too_large",
            "circuit_open",
        ] {
            let steps = remediation_steps(bucket, "some_node");
            assert!(
                steps
                    .iter()
                    .any(|s| s.get("tool").and_then(|t| t.as_str()) == Some("tail_worker_logs")),
                "remediation_steps({bucket}) does not name tail_worker_logs — the \
                 `[host:<policy>] … (target: …)` line is the only place the target \
                 and the precise policy variant appear"
            );
        }
    }

    /// The advice that was ACTIVELY WRONG, stated as the thing that must not
    /// come back.
    ///
    /// `remediation_steps("host_not_allowed")` says to widen `allowed_hosts`.
    /// Before this change every one of these causes answered that bucket. A
    /// playbook for a cause `allowed_hosts` cannot fix must not mention it as
    /// the remedy.
    #[test]
    fn no_denial_playbook_prescribes_a_fix_that_cannot_work() {
        for bucket in [
            "ssrf_blocked",
            "egress_tier_denied",
            "capability_world_denied",
            "insecure_scheme",
            "write_ceiling_denied",
            "introspection_denied",
        ] {
            let text = serde_json::to_string(&remediation_steps(bucket, "n")).unwrap();
            assert!(
                !text.contains("update_module_hosts"),
                "{bucket} prescribes update_module_hosts, which cannot resolve it"
            );
        }
        // The bucket where it IS the fix still says so.
        let text = serde_json::to_string(&remediation_steps("host_not_allowed", "n")).unwrap();
        assert!(text.contains("update_module_hosts"));
    }

    /// Every new bucket has a real playbook — not the `_` fall-through, which
    /// would tell the operator "this matched no specific gate" about a failure
    /// the host named precisely.
    #[test]
    fn every_new_bucket_has_its_own_playbook() {
        let fallthrough = serde_json::to_string(&remediation_steps("no_such_bucket", "n")).unwrap();
        for bucket in [
            "circuit_open",
            "execution_cancelled",
            "response_too_large",
            "request_too_large",
            "invalid_url",
            "insecure_scheme",
            "capability_world_denied",
            "ssrf_blocked",
            "egress_tier_denied",
            "write_ceiling_denied",
            "method_not_allowed",
            "egress_budget_exceeded",
            "introspection_denied",
        ] {
            let steps = remediation_steps(bucket, "my-node");
            assert!(!steps.is_empty(), "bucket {bucket} has no steps");
            assert_ne!(
                serde_json::to_string(&steps).unwrap(),
                fallthrough,
                "bucket {bucket} fell through to the generic playbook"
            );
            for (i, s) in steps.iter().enumerate() {
                assert_eq!(
                    s.get("step").and_then(|v| v.as_u64()),
                    Some(i as u64 + 1),
                    "bucket {bucket} step numbering broken"
                );
                assert!(s.get("description").is_some());
                assert!(s.get("action").is_some());
            }
        }
    }
}
