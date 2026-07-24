//! `http` host interface (fetch / fetch-all with host allowlists,
//! SSRF gates, vault:// header resolution and response caps).

use super::*;

use talos_idempotency::{DedupCheck, DedupResponse, InMemoryIdempotencyStore};

/// Process-global worker-side idempotency dedup store. Belt-and-suspenders ON
/// TOP OF the `Idempotency-Key` HTTP header (which is the primary dedup
/// mechanism): once a mutating send under a declared key completes with a 2xx
/// in THIS worker process, a subsequent send under the same key within the TTL
/// is short-circuited to the cached response instead of re-firing — covering
/// destinations that don't honor the header. Only engaged when the dispatch
/// carries an `idempotency_key` (opt-in); a non-declaring send never touches it.
///
/// Shared by `http::fetch` and `webhook::send` so a key used across both paths
/// dedupes consistently. TTL + entry cap are env-tunable
/// (`TALOS_WORKER_IDEMPOTENCY_TTL_SECS`, default 900;
/// `TALOS_WORKER_IDEMPOTENCY_MAX_ENTRIES`, default 10_000).
pub(crate) fn get_global_idempotency_store() -> &'static InMemoryIdempotencyStore {
    static STORE: std::sync::OnceLock<InMemoryIdempotencyStore> = std::sync::OnceLock::new();
    STORE.get_or_init(|| {
        let ttl_secs =
            talos_config::positive_env_or_default::<u64>("TALOS_WORKER_IDEMPOTENCY_TTL_SECS", 900);
        let max_entries = talos_config::positive_env_or_default::<usize>(
            "TALOS_WORKER_IDEMPOTENCY_MAX_ENTRIES",
            10_000,
        );
        InMemoryIdempotencyStore::new(std::time::Duration::from_secs(ttl_secs), max_entries)
    })
}

/// Whether an HTTP status represents a success worth caching for dedup. Only
/// 2xx: a non-2xx (4xx/5xx) must stay retryable, so we never cache it — a
/// retry re-fires and the transient classifier decides.
pub(crate) fn dedup_cacheable_status(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Whether an HTTP method mutates server state — the write-ceiling axis.
/// `GET` is the only read verb in `wit_http::Method`; every other verb
/// (`POST` / `PUT` / `PATCH` / `DELETE`) can mutate, so a read-only actor
/// is refused those under enforcement. Fail-safe by construction: the
/// `match` is exhaustive, so a future non-mutating verb added to the WIT
/// must be classified explicitly rather than defaulting to "read".
pub(crate) fn http_method_mutates(method: &wit_http::Method) -> bool {
    match method {
        wit_http::Method::Get => false,
        wit_http::Method::Post
        | wit_http::Method::Put
        | wit_http::Method::Patch
        | wit_http::Method::Delete => true,
    }
}

// ============================================================================
// HTTP
// ============================================================================

impl wit_http::Host for TalosContext {
    async fn fetch(
        &mut self,
        req: wit_http::Request,
    ) -> Result<wit_http::Response, wit_http::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result: Result<wit_http::Response, wit_http::Error> = async move {
        // Track async fuel consumption - HTTP operations consume fuel based on wall time
        let async_start = std::time::Instant::now();
        // MCP-789 (2026-05-14): the cheap pure-validation block (capability
        // gate, URL parse, empty allowlist, SSRF IP literal, allowed_hosts
        // pattern, Tier-1 LLM egress) MUST run BEFORE `check_rate_limit`
        // charges `http_call_count`. Pre-fix the rate-limit charge ran
        // FIRST, before even the capability gate. A guest could drain
        // MAX_HTTP_CALLS_PER_EXECUTION (1000/exec) by looping
        // `fetch(url="http://127.0.0.1/x")` (SSRF deny) or
        // `fetch(url="https://blocked.example.com/x")` (allowed_hosts
        // deny) and subsequent legitimate fetch() calls were then
        // blocked for the rest of the execution despite zero outbound
        // network I/O. The fetch_all batch variant was closed in
        // MCP-783; the single-fetch path was missed in that sweep.
        // Conservative reorder: rate-limit + cancellation moved AFTER
        // the cheap sync pure-validation block and BEFORE dry-run, so
        // dry-run STILL consumes a slot (preserves debug-quota
        // semantics) and DNS-rebind / method-allowlist / circuit-breaker
        // still run AFTER the charge (they involve I/O or atomic-state
        // reads that are legitimate per-call costs). Same shape as
        // MCP-770/783/784/785/786/787/788 and MCP-612 (counter-only-
        // advances-when-admitted).
        use crate::wit_inspector::CapabilityWorld;
        if matches!(
            self.capability_world,
            CapabilityWorld::Minimal | CapabilityWorld::Unknown
        ) {
            tracing::warn!("WASM module attempted HTTP request but lacks Http capability");
            return Err(wit_http::Error::Forbiddenhost);
        }
        // MCP-1148: cap URL bytes BEFORE invoking `url::Url::parse`.
        // The parser is O(N); a hostile guest could ship a 10 MB URL
        // and force the host to walk every byte on every call.
        if req.url.len() > MAX_OUTBOUND_URL_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                url_len = req.url.len(),
                limit = MAX_OUTBOUND_URL_BYTES,
                "wit_http::fetch rejected: URL length exceeds cap"
            );
            return Err(wit_http::Error::Invalidurl);
        }
        // Validate and parse the URL first.
        let url: url::Url = req.url.parse().map_err(|_| wit_http::Error::Invalidurl)?;

        // HTTPS-only by default. Plaintext outbound traffic can leak
        // `vault://` headers; the SSRF gate protects destination but
        // not data-in-flight. Operators with a legitimate plaintext
        // target opt in via `WASM_ALLOW_INSECURE_HTTP=1`.
        match classify_url_scheme(url.scheme(), insecure_http_opt_in()) {
            UrlSchemeVerdict::Https => {}
            UrlSchemeVerdict::InsecureAllowedByOptIn { scheme } => {
                tracing::warn!(
                    scheme = %scheme,
                    host = %url.host_str().unwrap_or(""),
                    "WASM module sent insecure-scheme HTTP request — \
                     allowed by WASM_ALLOW_INSECURE_HTTP=1 (operator opt-in). \
                     Confirm this is intended; plaintext traffic can leak vault:// \
                     headers in flight."
                );
            }
            UrlSchemeVerdict::InsecureRefused { scheme } => {
                self.record_capability_denied(
                    "http-fetch",
                    "insecure-scheme",
                    &format!("{scheme} {}", url.host_str().unwrap_or("")),
                )
                .await;
                tracing::warn!(
                    scheme = %scheme,
                    host = %url.host_str().unwrap_or(""),
                    "WASM module attempted non-https HTTP request — denied. \
                     Set WASM_ALLOW_INSECURE_HTTP=1 to permit plaintext outbound."
                );
                return Err(wit_http::Error::Invalidurl);
            }
        }

        // Enforce the host allowlist.  An empty list means DENY ALL — the module
        // must be configured with an explicit allowlist, or use "*" to allow any host.
        let host = url.host_str().unwrap_or("");
        // Structured trace for diagnosing vault:// and host-allowlist
        // rejections. Visible at RUST_LOG=worker=debug level.
        tracing::debug!(
            host,
            allowed_hosts_count = self.allowed_hosts.len(),
            allowed_secrets_count = self.allowed_secrets.len(),
            capability_world = ?self.capability_world,
            "http fetch dispatch"
        );
        if self.allowed_hosts.is_empty() {
            self.record_capability_denied("http-fetch", "no-allowlist-configured", host)
                .await;
            tracing::warn!(
                host,
                "WASM module attempted HTTP request but no host allowlist is configured — \
                 denying. Set WASM_ALLOWED_HOSTS=\"*\" to allow all hosts."
            );
            return Err(wit_http::Error::Forbiddenhost);
        }

        // DNS rebinding / SSRF protection: if the host parses as an IP address literal,
        // reject private, loopback, link-local, multicast, broadcast, and CGNAT ranges
        // immediately. This prevents a WASM module from using an IP literal to reach
        // internal services even when the allowlist contains a wildcard ("*").
        // SSRF: reject IP-literal hosts in denied ranges via the shared
        // chokepoint (covers IPv4 + IPv6 + CGNAT + IPv4-mapped). Blocks even
        // when the allowlist contains a wildcard ("*").
        if let Some((ip, policy)) = denied_ip_literal(&url) {
            self.record_capability_denied("http-fetch", policy, &ip.to_string())
                .await;
            tracing::warn!(
                ip = %ip,
                policy,
                "WASM module attempted to reach a private IP literal — blocking"
            );
            return Err(wit_http::Error::Forbiddenhost);
        }

        let host_match = match host_allowlist_match_kind(&self.allowed_hosts, host) {
            Some(kind) => kind,
            None => {
                self.record_capability_denied("http-fetch", "allowed-hosts", host)
                    .await;
                tracing::warn!(
                    host,
                    allowed_count = self.allowed_hosts.len(),
                    "WASM module attempted to reach a forbidden host"
                );
                return Err(wit_http::Error::Forbiddenhost);
            }
        };

        // Tier-1 LLM egress ceiling — deny external LLM provider hosts
        // regardless of `allowed_hosts`. Closes the HTTP bypass: a
        // Tier-1 guest can NOT reach `api.anthropic.com` even with
        // `api.anthropic.com` explicitly in `allowed_hosts` + its own
        // API key in `allowed_secrets`. This sits above the `llm::*`
        // host-fn ceiling: those gate key resolution; this gates the
        // network destination. Both are needed — a guest can bring its
        // own key (`config["api_key"]`) and bypass `llm::*` entirely.
        if matches!(
            self.max_llm_tier,
            talos_workflow_job_protocol::LlmTier::Tier1
        ) {
            let host_lower = host.to_ascii_lowercase();
            if let Some(policy) = tier1_egress_deny_reason(&host_lower) {
                self.record_capability_denied("http-fetch", policy, host)
                    .await;
                tracing::warn!(
                    host,
                    actor_id = ?self.actor_id,
                    policy,
                    "tier-1 actor egress refused (external LLM host or public IP literal)"
                );
                return Err(wit_http::Error::Forbiddenhost);
            }
        }

        // Write-ceiling gate: a read-only actor may issue read requests (GET)
        // but not mutating ones (POST / PUT / PATCH / DELETE). Pure decision,
        // in the cheap-validation block before the rate-limit charge. Inert
        // unless `TALOS_WRITE_CEILING_ENFORCED=1`.
        if http_method_mutates(&req.method)
            && self.write_ceiling_refuses("http-fetch", host).await
        {
            return Err(wit_http::Error::Forbiddenhost);
        }
        // Strict-egress gate for the READ side: a GET URL is guest-
        // influenceable outbound data (exfil channel), so with
        // `TALOS_WRITE_CEILING_STRICT_EGRESS=1` a read-only actor may
        // read only from operator-NAMED hosts — wildcard admissions are
        // refused. Inert unless both ceiling flags are on.
        if !http_method_mutates(&req.method)
            && self.read_egress_refuses("http-fetch", host, host_match).await
        {
            return Err(wit_http::Error::Forbiddenhost);
        }

        // Rate limit + cancellation: charged AFTER the cheap pure-validation
        // block above — see MCP-789 reorder comment near the top of this
        // function. Charged BEFORE dry-run so dry-run still consumes a slot
        // (preserves debug-quota semantics), and BEFORE the DNS-rebind
        // lookup so DNS work is bounded by the rate-limit too.
        if !self.check_rate_limit(&self.http_call_count, MAX_HTTP_CALLS_PER_EXECUTION) {
            tracing::warn!(module_id = ?self.module_id, "HTTP call rate limit exceeded");
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("http");
            }
            return Err(wit_http::Error::Forbiddenhost);
        }
        // M-6: per-host rate limit charged AFTER the global cap admits.
        // Failure here yields the global counter back? — no, intentionally
        // not: the global cap is the worker-level budget for compute spent
        // on validation + DNS + setup, and a per-host overage still cost
        // that effort. Burning the global slot keeps the abuse pattern
        // expensive for the attacker. The host string is normalized to
        // host:port (lowercased) inside `check_per_host_rate_limit`.
        let host_for_limit = match url.port_or_known_default() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        if !self.check_per_host_rate_limit(
            &host_for_limit,
            MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION,
        ) {
            tracing::warn!(
                module_id = ?self.module_id,
                host = %host,
                limit = MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION,
                "HTTP per-host rate limit exceeded — refusing to amplify load to a single upstream"
            );
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("http_per_host");
            }
            return Err(wit_http::Error::Forbiddenhost);
        }
        if self.is_cancelled() {
            tracing::info!(module_id = ?self.module_id, "Execution cancelled");
            if let Some(ref m) = self.metrics {
                m.record_execution_cancelled();
            }
            return Err(wit_http::Error::Networkerror);
        }

        // Dry-run mode: mock non-GET HTTP requests BEFORE any network
        // operation (DNS, circuit breaker, real HTTP). The previous
        // location (after DNS resolution) meant that a POST to a
        // non-resolvable hostname — i.e. exactly the URLs you'd use
        // to test workflow logic without side effects — failed with
        // a generic Networkerror instead of being intercepted.
        //
        // Policy checks above this point still apply (allowed_hosts +
        // IP-literal SSRF), so misconfigured allowlists still surface
        // as Forbiddenhost during dry-run testing. Method allowlist
        // and circuit-breaker are intentionally skipped here — neither
        // is meaningful for traffic that will never leave the worker.
        if self.dry_run {
            let dry_method = match req.method {
                wit_http::Method::Get => "GET",
                wit_http::Method::Post => "POST",
                wit_http::Method::Put => "PUT",
                wit_http::Method::Delete => "DELETE",
                wit_http::Method::Patch => "PATCH",
            };
            if dry_method != "GET" {
                tracing::info!(
                    method = dry_method,
                    url = %req.url,
                    "Dry-run: intercepted non-GET request (pre-network)"
                );
                let mock_body = serde_json::to_vec(&serde_json::json!({
                    "__dry_run__": true,
                    "intercepted_method": dry_method,
                    "intercepted_url": req.url,
                }))
                .unwrap_or_default();
                return Ok(wit_http::Response {
                    status: 200,
                    headers: vec![("x-talos-dry-run".to_string(), "true".to_string())],
                    body: mock_body,
                });
            }
        }

        // ── DNS resolution validation (SSRF protection) ────────────────────
        // For hostnames (not IP literals), resolve DNS and verify the resolved
        // IP is not a private/internal address. This prevents DNS rebinding attacks
        // where an attacker controls a domain that resolves to internal IPs.
        //
        // Operator opt-in: WORKER_ALLOW_PRIVATE_HOST_TARGETS=1 disables the
        // DNS-resolved-to-private rejection, but ONLY for hostnames that are
        // explicitly named in `allowed_hosts` (not via "*"). This narrow
        // bypass enables the local-development case where the worker reaches
        // a sibling service (e.g. nova on host.docker.internal:3030) while
        // keeping the wildcard-allowlist case fully protected. IP literals
        // are still rejected unconditionally above.
        let bypass_dns_ssrf = *ALLOW_PRIVATE_HOST_TARGETS
            && self
                .allowed_hosts
                .iter()
                .any(|p| p != "*" && p == host);
        if url
            .host()
            .is_some_and(|h| matches!(h, url::Host::Domain(_)))
            && !bypass_dns_ssrf
        {
            match tokio::net::lookup_host(format!("{}:80", host)).await {
                Ok(addrs) => {
                    for addr in addrs {
                        let ip = addr.ip();
                        // Same deny-list as the IP-literal arm above —
                        // shared via classify_private_ip so CGNAT and
                        // IPv4-mapped IPv6 stay covered without drift.
                        // This is the DNS-rebinding defence: a hostname
                        // under attacker DNS control could otherwise
                        // resolve to ::ffff:127.0.0.1 or 100.64.x.x at
                        // request time and bypass an allowlist entry.
                        if let Some(policy) = classify_private_ip(ip) {
                            self.record_capability_denied(
                                "http-fetch",
                                policy,
                                &ip.to_string(),
                            )
                            .await;
                            tracing::warn!(
                                host = %host,
                                ip = %ip,
                                policy,
                                allow_private_env = "WORKER_ALLOW_PRIVATE_HOST_TARGETS",
                                "WASM module blocked: hostname resolved to a private IP. \
                                 If intentional (e.g. worker reaching a sibling service), \
                                 set WORKER_ALLOW_PRIVATE_HOST_TARGETS=true AND list \
                                 '{host}' explicitly in allowed_hosts (not via '*'). \
                                 IP literals to private ranges remain blocked unconditionally.",
                                host = host,
                            );
                            return Err(wit_http::Error::Forbiddenhost);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        host = %host,
                        error = %e,
                        "Failed to resolve hostname for SSRF validation"
                    );
                    // Fixed-text reason (no resolver error string — it can
                    // embed infra detail); distinguishes the DNS-outage
                    // class from every policy deny that shares this enum.
                    self.emit_host_diagnostic(
                        "dns-resolution-failed",
                        &format!(
                            "hostname resolution failed for '{host}' — DNS unavailable \
                             or name does not exist; the request was not sent"
                        ),
                    )
                    .await;
                    return Err(wit_http::Error::Networkerror);
                }
            }
        } else if bypass_dns_ssrf {
            tracing::debug!(
                host,
                "DNS-SSRF bypass active (WORKER_ALLOW_PRIVATE_HOST_TARGETS=1 + explicit allowlist hit)"
            );
        }

        // Enforce method allowlist (empty = allow all methods).
        let method_str = match req.method {
            wit_http::Method::Get => "GET",
            wit_http::Method::Post => "POST",
            wit_http::Method::Put => "PUT",
            wit_http::Method::Delete => "DELETE",
            wit_http::Method::Patch => "PATCH",
        };
        if !self.allowed_methods.is_empty()
            && !self
                .allowed_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(method_str))
        {
            self.record_capability_denied(
                "http-fetch",
                "method-allowlist",
                &format!("{} {}", method_str, host),
            )
            .await;
            tracing::warn!(
                host,
                method = method_str,
                allowed_methods = ?self.allowed_methods,
                "WASM module attempted a disallowed HTTP method"
            );
            return Err(wit_http::Error::Forbiddenhost);
        }

        // Check circuit breaker before making request
        let host_str = host.to_string();
        if !get_global_circuit_breaker().allow_request(&host_str) {
            tracing::warn!(host = %host, "Circuit breaker open - rejecting HTTP request");
            self.emit_host_diagnostic(
                "circuit-breaker-open",
                &format!(
                    "circuit breaker open for '{host}' after recent failures — \
                     request rejected without being sent; it closes automatically"
                ),
            )
            .await;
            return Err(wit_http::Error::Networkerror);
        }

        // Build the async reqwest request
        let method = req.method;
        // MCP-1105 (2026-05-16): cap header count BEFORE the body-size
        // / per-header vault-resolve loop. Pre-fix loop at line ~1893
        // called `resolve_vault_header` (DB call) per header with no
        // bound — see the MAX_OUTBOUND_HEADERS doc-comment for the
        // full attack surface.
        if req.headers.len() > MAX_OUTBOUND_HEADERS {
            tracing::warn!(
                module_id = ?self.module_id,
                header_count = req.headers.len(),
                limit = MAX_OUTBOUND_HEADERS,
                "wit_http::fetch rejected: header count exceeds cap"
            );
            return Err(wit_http::Error::Forbiddenhost);
        }
        let headers = req.headers.clone();
        // MCP-1014 (2026-05-15): cap caller-supplied body size. Same
        // sibling-drift class as wit_webhook::send below. wasmtime's
        // WASM-memory bound is the floor not the ceiling of host
        // memory commitment — every send clones the body once into
        // this binding and again into reqwest. Cap at 10 MB matching
        // the wit_webhook + wit_messaging + wit_data_transform caps.
        // MCP-1076: canonical module-level MAX_OUTBOUND_HTTP_BODY_BYTES.
        if req.body.len() > MAX_OUTBOUND_HTTP_BODY_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                body_len = req.body.len(),
                limit = MAX_OUTBOUND_HTTP_BODY_BYTES,
                "wit_http::fetch rejected: body exceeds cap"
            );
            return Err(wit_http::Error::Forbiddenhost);
        }
        let body = req.body.clone();
        // MCP-584: clamp caller-supplied timeout to MAX_HTTP_TIMEOUT_MS
        // (120 s). Pre-fix `req.timeout_ms` was `option<u32>` with no
        // upper bound — a module could pass `u32::MAX` (~50 days) and
        // hold a TCP connection (and the worker thread awaiting it)
        // open for the full duration. Async fuel tracking is
        // observation-only today (consume_async_fuel returns the cost
        // but doesn't deduct it from the store), so the WASM execution
        // budget doesn't bound this naturally. Cap matches the
        // wit_agent_orchestration::invoke convention at line 6095
        // (`timeout_ms.min(120_000)`); same fix applied to fetch_all
        // and execute_graphql_inner below.
        let timeout_ms = req.timeout_ms.unwrap_or(30_000).min(MAX_HTTP_TIMEOUT_MS) as u64;
        let url_str = req.url.clone();

        let client = self.http_client.clone();

        let reqwest_method = match method {
            wit_http::Method::Get => reqwest::Method::GET,
            wit_http::Method::Post => reqwest::Method::POST,
            wit_http::Method::Put => reqwest::Method::PUT,
            wit_http::Method::Delete => reqwest::Method::DELETE,
            wit_http::Method::Patch => reqwest::Method::PATCH,
        };

        // Dry-run interception now happens earlier (before DNS) — this
        // path is only reached for non-dry-run runs, which proceed to
        // build and send the real request below.

        let method_str_for_audit = reqwest_method.as_str().to_string();
        let mut builder = client
            .request(reqwest_method, &url_str)
            .timeout(std::time::Duration::from_millis(timeout_ms));
        for (name, value) in &headers {
            let resolved = self
                .resolve_vault_header(name.as_str(), value.as_str())
                .await
                .map_err(|_| wit_http::Error::Forbiddenhost)?;
            builder = builder.header(name.as_str(), resolved.as_ref());
        }
        // Opt-in idempotency (Task 3): when the engine stamped a stable
        // idempotency key for this dispatch (the node declared
        // `__idempotency_key__`), emit it as the industry-standard
        // `Idempotency-Key` header on MUTATING requests so a retried send is
        // deduplicated at the destination (Stripe-style). Only for mutating
        // verbs (a GET is already safe to retry and needs no key), and only when
        // the guest hasn't set the header itself (respect an explicit override).
        //
        // `dedup_key` mirrors that decision: when set, this send participates in
        // the worker-side in-memory dedup store (Task 2) as belt-and-suspenders
        // for destinations that don't honor the header. We do NOT engage the
        // store when the guest set its own key (we don't know its dedup
        // semantics) — only for the engine-stamped, header-emitting case.
        let mut dedup_key: Option<String> = None;
        if http_method_mutates(&method) {
            if let Some(ref idem) = self.idempotency_key {
                let guest_set = headers
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case("idempotency-key"));
                if !guest_set {
                    builder = builder.header("Idempotency-Key", idem.as_str());
                    dedup_key = Some(idem.clone());
                }
            }
        }
        // Task 2: short-circuit a mutating send whose engine-stamped key already
        // COMPLETED successfully in this process — return the cached response
        // instead of re-firing. Covers destinations with no Idempotency-Key
        // support. A miss (or a non-declaring send) proceeds normally.
        if let Some(ref k) = dedup_key {
            if let DedupCheck::Completed(cached) = get_global_idempotency_store().check(k) {
                tracing::info!(
                    host = %host_str,
                    "idempotent send short-circuited: returning cached response for a \
                     previously-completed idempotency key (worker-side dedup)"
                );
                // `return` here resolves the enclosing `async move` block (whose
                // value the outer fn records metrics for and returns) — NOT the
                // outer fn, so metrics are still recorded once at the tail.
                self.consume_async_fuel(async_start.elapsed(), "http::fetch");
                return Ok(wit_http::Response {
                    status: cached.status,
                    headers: cached.headers,
                    body: cached.body,
                });
            }
        }
        if !body.is_empty() {
            builder = builder.body(body.clone());
        }

        let response = match builder.send().await {
            Ok(resp) => {
                get_global_circuit_breaker().record_success(&host_str);
                resp
            }
            Err(e) => {
                get_global_circuit_breaker().record_failure(&host_str);
                if e.is_timeout() {
                    self.emit_host_diagnostic(
                        "request-timeout",
                        &format!("request to '{host_str}' timed out"),
                    )
                    .await;
                    return Err(wit_http::Error::Timeout);
                }
                if e.is_connect()
                    && self.max_llm_tier == talos_workflow_job_protocol::LlmTier::Tier1
                {
                    // A Tier-1 (local-egress-only) actor's SsrfFilteringResolver
                    // drops every public IP, so a connect failure to a
                    // non-loopback host is almost always the data-egress gate
                    // — NOT the host being down. Say so with the fix, since the
                    // resolver itself (a reqwest dns::Resolve impl) has no
                    // TalosContext to emit from. Loopback/private targets still
                    // connect under Tier-1 (local Ollama), so those failures
                    // produce the generic reason below.
                    self.emit_host_diagnostic(
                        "tier1-egress-blocked",
                        &format!(
                            "'{host_str}' was blocked by this workflow's Tier-1 actor \
                             (local-egress-only — data must not leave the host). To reach \
                             an external API, bind the workflow to a Tier-2 actor."
                        ),
                    )
                    .await;
                    return Err(wit_http::Error::Networkerror);
                }
                // Class only — reqwest's Display can embed proxy /
                // internal-infra detail, and the connect-vs-reset
                // distinction is all the module author needs.
                let class = if e.is_connect() {
                    "connection failed (refused/unreachable)"
                } else {
                    "request failed after connecting (reset/protocol)"
                };
                self.emit_host_diagnostic(
                    "connection-failed",
                    &format!("request to '{host_str}': {class}"),
                )
                .await;
                return Err(wit_http::Error::Networkerror);
            }
        };

        let status = response.status().as_u16();
        tracing::info!(
            method = %method_str_for_audit,
            host = %url.host_str().unwrap_or("unknown"),
            path = %url.path(),
            status = status,
            "HTTP audit"
        );
        // MCP-1114: cap inbound header count + per-value size.
        // External server could otherwise materialise unbounded host
        // RAM via 10k+ headers (HTTP/2) or multi-MB header values.
        if response.headers().len() > MAX_INBOUND_HEADERS {
            tracing::warn!(
                module_id = ?self.module_id,
                header_count = response.headers().len(),
                limit = MAX_INBOUND_HEADERS,
                "wit_http::fetch response rejected: header count exceeds cap"
            );
            return Err(wit_http::Error::Networkerror);
        }
        let resp_headers: Vec<(String, String)> = {
            let mut out: Vec<(String, String)> = Vec::with_capacity(response.headers().len());
            for (k, v) in response.headers().iter() {
                if v.as_bytes().len() > MAX_INBOUND_HEADER_VALUE_BYTES {
                    tracing::warn!(
                        module_id = ?self.module_id,
                        header = %k,
                        value_len = v.as_bytes().len(),
                        limit = MAX_INBOUND_HEADER_VALUE_BYTES,
                        "wit_http::fetch response rejected: header value exceeds cap"
                    );
                    return Err(wit_http::Error::Networkerror);
                }
                out.push((
                    k.to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                ));
            }
            out
        };
        // Enforce configurable response size limit to prevent OOM.
        // MCP-670 (2026-05-13): route through `positive_env_or_default`
        // so `WASM_HTTP_MAX_RESPONSE_BYTES=0` (a real Helm placeholder
        // pattern) doesn't reject every fetch with "payload too large
        // (0 > 0)". Sibling to MCP-639/642/643/665/668 — the `=0`
        // env-var footgun family.
        const DEFAULT_MAX_RESPONSE: usize = 10 * 1024 * 1024; // 10 MiB
        let max_resp = talos_config::positive_env_or_default::<usize>(
            "WASM_HTTP_MAX_RESPONSE_BYTES",
            DEFAULT_MAX_RESPONSE,
        );

        // Prevent OOM by reading chunks up to max_resp.
        let content_length = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        let capacity = std::cmp::min(content_length, max_resp);
        let mut resp_body_bytes = Vec::with_capacity(capacity);
        let mut stream = response.bytes_stream();
        use futures_util::StreamExt;
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|_| wit_http::Error::Networkerror)?;
            if resp_body_bytes.len() + chunk.len() > max_resp {
                tracing::warn!(
                    limit = max_resp,
                    "HTTP response exceeds size limit during streaming"
                );
                return Err(wit_http::Error::Networkerror);
            }
            resp_body_bytes.extend_from_slice(&chunk);
        }
        let resp_body = resp_body_bytes;

        // Track async fuel consumption - HTTP wall time converts to fuel cost
        // Approximate: 1ms ≈ 10,000 WASM instructions
        let async_elapsed = async_start.elapsed();
        self.consume_async_fuel(async_elapsed, "http::fetch");

        // Task 2: on a SUCCESSFUL (2xx) idempotent send, record the response so a
        // later send under the same engine-stamped key is short-circuited. Only
        // 2xx is cached — a 4xx/5xx must stay retryable. Non-declaring sends
        // (`dedup_key == None`) never touch the store.
        if let Some(ref k) = dedup_key {
            if dedup_cacheable_status(status) {
                get_global_idempotency_store().complete(
                    k,
                    DedupResponse {
                        status,
                        headers: resp_headers.clone(),
                        body: resp_body.clone(),
                    },
                );
            }
        }

        Ok(wit_http::Response {
            status,
            headers: resp_headers,
            body: resp_body,
        })
        }.await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call("http::fetch", __start.elapsed().as_millis() as f64);
        }
        __result
    }

    /// Dispatch multiple HTTP requests concurrently.)
    ///
    /// Security model: each request undergoes the same per-request validation
    /// (capability world, SSRF/IP check, host allowlist, method allowlist) as
    /// individual `fetch` calls.  Rate-limit budget is consumed atomically
    /// upfront for the entire batch before any network I/O begins — if the
    /// batch would exceed the budget the whole call fails fast with
    /// `Forbiddenhost` rather than partially succeeding.
    async fn fetch_all(
        &mut self,
        reqs: Vec<wit_http::Request>,
    ) -> Vec<Result<wit_http::Response, wit_http::Error>> {
        if reqs.is_empty() {
            return Vec::new();
        }

        // ── Global pre-flight checks (require &mut self) ─────────────────────
        if self.is_cancelled() {
            return reqs
                .iter()
                .map(|_| Err(wit_http::Error::Networkerror))
                .collect();
        }
        use crate::wit_inspector::CapabilityWorld;
        if matches!(
            self.capability_world,
            CapabilityWorld::Minimal | CapabilityWorld::Unknown
        ) {
            tracing::warn!("fetch_all: module lacks Http capability");
            return reqs
                .iter()
                .map(|_| Err(wit_http::Error::Forbiddenhost))
                .collect();
        }

        // ── Per-request validation ────────────────────────────────────────
        // Async for-loop (not `.iter().map()`) because every deny path
        // emits an audit event via `record_capability_denied`, and vault
        // header resolution is async. Inline audits keep the per-batch
        // hash-chain ordering equal to the request order in `reqs` — no
        // separate buffer-then-drain dance. Checks are ordered cheap-first
        // so we never do a DNS lookup or vault resolution for a request
        // we'll reject on a sync check anyway.
        let bypass_dns_env = *ALLOW_PRIVATE_HOST_TARGETS;

        #[allow(clippy::type_complexity)]
        let mut validated: Vec<
            Result<(String, reqwest::Method, Vec<(String, String)>, Vec<u8>, u64), wit_http::Error>,
        > = Vec::with_capacity(reqs.len());

        for req in &reqs {
            // MCP-1014 (2026-05-15): cap caller-supplied body size before
            // any URL parse / DNS / vault work. Same sibling-drift class
            // as wit_http::fetch and wit_webhook::send. Each entry in the
            // batch gets cloned twice (once into `validated`, once into
            // reqwest); a single batch entry over 10 MB would multiply
            // through buffer_unordered concurrency. Reject early; the
            // batch carries on with other entries.
            // MCP-1076: canonical module-level MAX_OUTBOUND_HTTP_BODY_BYTES.
            if req.body.len() > MAX_OUTBOUND_HTTP_BODY_BYTES {
                tracing::warn!(
                    module_id = ?self.module_id,
                    body_len = req.body.len(),
                    limit = MAX_OUTBOUND_HTTP_BODY_BYTES,
                    "fetch_all: per-request body exceeds cap"
                );
                validated.push(Err(wit_http::Error::Forbiddenhost));
                continue;
            }

            // MCP-1148: per-entry URL byte cap. fetch_all amplifies the
            // single-fetch URL-parse-cost concern by `batch_size` —
            // 64-entry batches with 10 MB URLs each would otherwise
            // pay 640 MB of parse work per batch fire.
            if req.url.len() > MAX_OUTBOUND_URL_BYTES {
                tracing::warn!(
                    module_id = ?self.module_id,
                    url_len = req.url.len(),
                    limit = MAX_OUTBOUND_URL_BYTES,
                    "fetch_all: per-request URL exceeds cap"
                );
                validated.push(Err(wit_http::Error::Invalidurl));
                continue;
            }

            // 1. URL parse.
            let url: url::Url = match req.url.parse() {
                Ok(u) => u,
                Err(_) => {
                    validated.push(Err(wit_http::Error::Invalidurl));
                    continue;
                }
            };
            let host = url.host_str().unwrap_or("").to_string();

            // 1b. HTTPS-only by default (see `classify_url_scheme` doc).
            // Operator opt-in via `WASM_ALLOW_INSECURE_HTTP=1`.
            match classify_url_scheme(url.scheme(), insecure_http_opt_in()) {
                UrlSchemeVerdict::Https => {}
                UrlSchemeVerdict::InsecureAllowedByOptIn { scheme } => {
                    tracing::warn!(
                        scheme = %scheme,
                        host = %host,
                        "fetch_all: insecure-scheme request allowed by WASM_ALLOW_INSECURE_HTTP=1"
                    );
                }
                UrlSchemeVerdict::InsecureRefused { scheme } => {
                    self.record_capability_denied(
                        "http-fetch-all",
                        "insecure-scheme",
                        &format!("{scheme} {host}"),
                    )
                    .await;
                    validated.push(Err(wit_http::Error::Invalidurl));
                    continue;
                }
            }

            // 2. Allowlist must be configured.
            if self.allowed_hosts.is_empty() {
                self.record_capability_denied("http-fetch-all", "no-allowlist-configured", &host)
                    .await;
                validated.push(Err(wit_http::Error::Forbiddenhost));
                continue;
            }

            // 3. SSRF: classify IP literals (no network I/O).
            //    Single source of truth in classify_private_ip — covers
            //    CGNAT and IPv4-mapped IPv6 too.
            if let Some((ip, policy)) = denied_ip_literal(&url) {
                self.record_capability_denied("http-fetch-all", policy, &ip.to_string())
                    .await;
                validated.push(Err(wit_http::Error::Forbiddenhost));
                continue;
            }

            // 4. allowed_hosts pattern match.
            let host_match = match host_allowlist_match_kind(&self.allowed_hosts, &host) {
                Some(kind) => kind,
                None => {
                    self.record_capability_denied("http-fetch-all", "allowed-hosts", &host)
                        .await;
                    validated.push(Err(wit_http::Error::Forbiddenhost));
                    continue;
                }
            };

            // 5. Tier-1 LLM egress ceiling. Per-request so a mixed batch
            //    rejects only the tier-2 LLM entries.
            if matches!(
                self.max_llm_tier,
                talos_workflow_job_protocol::LlmTier::Tier1
            ) {
                let host_lower = host.to_ascii_lowercase();
                if let Some(policy) = tier1_egress_deny_reason(&host_lower) {
                    self.record_capability_denied("http-fetch-all", policy, &host)
                        .await;
                    tracing::warn!(
                        host = %host,
                        actor_id = ?self.actor_id,
                        policy,
                        "tier-1 actor fetch_all egress refused (external LLM host or public IP literal)"
                    );
                    validated.push(Err(wit_http::Error::Forbiddenhost));
                    continue;
                }
            }

            // 5b. Write-ceiling gate: read-only actors may GET but not
            //     mutate. Per-request so a mixed batch rejects only the
            //     mutating entries. Inert unless enforcement is on.
            if http_method_mutates(&req.method)
                && self.write_ceiling_refuses("http-fetch-all", &host).await
            {
                validated.push(Err(wit_http::Error::Forbiddenhost));
                continue;
            }
            // 5c. Strict-egress gate for the READ side (see the fetch()
            //     sibling): read-only actors may read only from
            //     operator-NAMED hosts; wildcard admissions refused.
            if !http_method_mutates(&req.method)
                && self
                    .read_egress_refuses("http-fetch-all", &host, host_match)
                    .await
            {
                validated.push(Err(wit_http::Error::Forbiddenhost));
                continue;
            }

            // 6. HTTP method allowlist.
            let method_str = match req.method {
                wit_http::Method::Get => "GET",
                wit_http::Method::Post => "POST",
                wit_http::Method::Put => "PUT",
                wit_http::Method::Delete => "DELETE",
                wit_http::Method::Patch => "PATCH",
            };
            if !self.allowed_methods.is_empty()
                && !self
                    .allowed_methods
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(method_str))
            {
                self.record_capability_denied(
                    "http-fetch-all",
                    "method-allowlist",
                    &format!("{} {}", method_str, host),
                )
                .await;
                validated.push(Err(wit_http::Error::Forbiddenhost));
                continue;
            }

            // M-6: per-host rate limit applied per-entry, BEFORE the
            // global counter bump below. A batch with 200 entries all
            // targeting the same host gets the first
            // MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION admitted and the
            // rest rejected — partial-success, same shape as the
            // sibling per-request validation checks above. This
            // prevents `fetch_all` from being a per-host-limit
            // bypass.
            let host_for_limit = match url.port_or_known_default() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            };
            if !self
                .check_per_host_rate_limit(&host_for_limit, MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION)
            {
                self.record_capability_denied(
                    "http-fetch-all",
                    "per-host-rate-limit",
                    &host_for_limit,
                )
                .await;
                validated.push(Err(wit_http::Error::Forbiddenhost));
                continue;
            }

            // 7. DNS-rebinding SSRF check for hostname URLs. Resolve the
            //    hostname and classify each resolved IP via the same
            //    helper used for IP literals — closes the rebinding gap
            //    where an attacker-controlled domain could resolve to
            //    127.0.0.1 / ::ffff:127.0.0.1 / 100.64.x.x at request
            //    time. Bypass requires WORKER_ALLOW_PRIVATE_HOST_TARGETS
            //    AND an explicit (non-wildcard) allowlist entry.
            //
            //    Serial across the batch — fetch_all batches are typically
            //    a handful of well-known hosts and the OS resolver caches
            //    common entries, so the wall-clock cost is dominated by
            //    the actual HTTP request, not the lookup.
            let is_hostname = matches!(url.host(), Some(url::Host::Domain(_)));
            let bypass_dns =
                bypass_dns_env && self.allowed_hosts.iter().any(|p| p != "*" && p == &host);
            if is_hostname && !bypass_dns {
                match tokio::net::lookup_host(format!("{}:80", host)).await {
                    Ok(addrs) => {
                        let mut blocked: Option<(&'static str, std::net::IpAddr)> = None;
                        for addr in addrs {
                            let ip = addr.ip();
                            if let Some(policy) = classify_private_ip(ip) {
                                blocked = Some((policy, ip));
                                break;
                            }
                        }
                        if let Some((policy, ip)) = blocked {
                            self.record_capability_denied(
                                "http-fetch-all",
                                policy,
                                &ip.to_string(),
                            )
                            .await;
                            tracing::warn!(
                                host = %host,
                                ip = %ip,
                                policy,
                                "fetch_all: hostname resolved to a private IP — blocking"
                            );
                            validated.push(Err(wit_http::Error::Forbiddenhost));
                            continue;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            host = %host,
                            error = %e,
                            "fetch_all: DNS resolution failed for SSRF check"
                        );
                        validated.push(Err(wit_http::Error::Networkerror));
                        continue;
                    }
                }
            }

            // 8. Resolve vault:// headers (async — see resolve_vault_header).
            //    Deny audits emit inside resolve_vault_header itself; this
            //    site only translates the Err to wit_http::Error.
            // MCP-1105: per-entry header cap. See MAX_OUTBOUND_HEADERS
            // doc-comment for the rationale.
            if req.headers.len() > MAX_OUTBOUND_HEADERS {
                tracing::warn!(
                    module_id = ?self.module_id,
                    header_count = req.headers.len(),
                    limit = MAX_OUTBOUND_HEADERS,
                    "wit_http::fetch_all entry rejected: header count exceeds cap"
                );
                validated.push(Err(wit_http::Error::Forbiddenhost));
                continue;
            }
            let reqwest_method = match req.method {
                wit_http::Method::Get => reqwest::Method::GET,
                wit_http::Method::Post => reqwest::Method::POST,
                wit_http::Method::Put => reqwest::Method::PUT,
                wit_http::Method::Delete => reqwest::Method::DELETE,
                wit_http::Method::Patch => reqwest::Method::PATCH,
            };
            let mut hdrs: Vec<(String, String)> = Vec::with_capacity(req.headers.len());
            let mut header_failed = false;
            for (k, v) in &req.headers {
                match self.resolve_vault_header(k.as_str(), v.as_str()).await {
                    Ok(resolved) => hdrs.push((k.clone(), resolved.into_owned())),
                    Err(_) => {
                        header_failed = true;
                        break;
                    }
                }
            }
            if header_failed {
                validated.push(Err(wit_http::Error::Forbiddenhost));
                continue;
            }

            validated.push(Ok((
                req.url.clone(),
                reqwest_method,
                hdrs,
                req.body.clone(),
                // MCP-584: clamp per-request timeout in fetch_all
                // exactly as fetch above. Each entry in the batch
                // could otherwise pass u32::MAX and tie up a slot in
                // the buffer_unordered pool.
                req.timeout_ms.unwrap_or(30_000).min(MAX_HTTP_TIMEOUT_MS) as u64,
            )));
        }

        // MCP-783 (2026-05-14): consume rate-limit budget only for entries
        // that passed per-request validation. Pre-fix `fetch_add(batch_size)`
        // ran BEFORE the validation loop, so a batch of N entries all
        // failing per-request checks (SSRF, allowed-hosts, method
        // allowlist, DNS-rebind, vault-resolve) burned N against
        // MAX_HTTP_CALLS_PER_EXECUTION even though zero HTTP calls
        // actually went out. Repeated burst calls of validation-failing
        // batches could exhaust the per-execution HTTP budget, blocking
        // subsequent legitimate calls. Same shape as MCP-770
        // (wit_files::write charged byte quota before path sanitization)
        // and MCP-612 (the original counter-only-advances-when-admitted
        // rule called out in `Context::check_rate_limit`'s docstring).
        // Validation-failed entries also now preserve their specific
        // Error (Invalidurl, Forbiddenhost, Networkerror) on overflow —
        // the old overflow path collapsed every return slot to
        // Forbiddenhost regardless of why a particular entry was
        // rejected, losing operator-visibility into the actual cause.
        let actual_calls = validated.iter().filter(|v| v.is_ok()).count() as u64;
        let prev = self
            .http_call_count
            .fetch_add(actual_calls, std::sync::atomic::Ordering::Relaxed);
        if prev + actual_calls > MAX_HTTP_CALLS_PER_EXECUTION {
            // Refund the slots we just claimed — the batch is rejected.
            self.http_call_count
                .fetch_sub(actual_calls, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(module_id = ?self.module_id, "fetch_all: HTTP call rate limit exceeded");
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("http");
            }
            return validated
                .into_iter()
                .map(|v| match v {
                    Ok(_) => Err(wit_http::Error::Forbiddenhost),
                    Err(e) => Err(e),
                })
                .collect();
        }

        // ── Concurrent dispatch ───────────────────────────────────────────────
        // MCP-670 (2026-05-13): same `=0`-safe helper as the single-fetch path.
        let max_resp = talos_config::positive_env_or_default::<usize>(
            "WASM_HTTP_MAX_RESPONSE_BYTES",
            10 * 1024 * 1024_usize,
        );

        // ── Concurrent dispatch with backpressure ─────────────────────────
        // Use buffer_unordered to limit concurrent requests and prevent
        // resource exhaustion when processing large batches.
        //
        // MCP-1109 (2026-05-16): LazyLock-cached + routed through
        // `positive_env_or_default`. Pre-fix this site paid a per-call
        // `env::var` (process-wide environ-mutex lock + String alloc)
        // on every WASM `fetch_all` invocation AND used the raw
        // `.parse().ok().unwrap_or(10).clamp(1, 100)` shape, which is
        // sibling drift from the canonical `=0`-safe helper. The shape
        // mismatch gave a subtly different semantic: `FETCH_ALL_CONCURRENCY=0`
        // (real Helm placeholder pattern) clamped UP to 1 instead of
        // falling through to the default 10 the way every other
        // worker-env site in this file does (MCP-670/665/668 family,
        // and the sibling `WASM_HTTP_MAX_RESPONSE_BYTES` two lines
        // above). Operators reasoning about `=0` semantics across
        // worker envs now see one rule: `=0` → default + WARN. Upper
        // bound stays at 100 to prevent runaway concurrency from a
        // misconfigured `FETCH_ALL_CONCURRENCY=10000`.
        const DEFAULT_CONCURRENCY: usize = 10;
        static FETCH_ALL_CONCURRENCY_LIMIT: std::sync::LazyLock<usize> =
            std::sync::LazyLock::new(|| {
                talos_config::positive_env_or_default::<usize>(
                    "FETCH_ALL_CONCURRENCY",
                    DEFAULT_CONCURRENCY,
                )
                .min(100)
            });
        let concurrency_limit = *FETCH_ALL_CONCURRENCY_LIMIT;

        let self_http_client = self.http_client.clone();
        let dry_run = self.dry_run;
        // Host per input slot, captured BEFORE the entries move into the
        // stream — used after the join to emit per-failure diagnostics.
        // None = the entry already failed validation (its deny was
        // diagnosed at validation time via record_capability_denied).
        let request_hosts: Vec<Option<String>> = validated
            .iter()
            .map(|v| {
                v.as_ref().ok().and_then(|(u, _, _, _, _)| {
                    url::Url::parse(u)
                        .ok()
                        .and_then(|p| p.host_str().map(str::to_string))
                })
            })
            .collect();
        let stream =
            futures_util::stream::iter(validated.into_iter().enumerate().map(move |(idx, v)| {
                let max_r = max_resp;
                let self_http_client = self_http_client.clone();
                async move {
                    // Tag every future with its INPUT index: buffer_unordered
                    // yields in COMPLETION order, and the WIT contract
                    // promises `responses[i]` corresponds to `requests[i]`.
                    // Pre-fix, any batch whose requests finished out of
                    // order returned misattributed responses (silent
                    // cross-request data mix-up under the default
                    // concurrency of 10). The post-join sort restores the
                    // documented order.
                    let result = async move {
                        let (url_str, method, headers, body, timeout_ms) = match v {
                            Err(e) => return Err(e),
                            Ok(params) => params,
                        };

                // Dry-run mode: mock non-GET HTTP requests
                if dry_run && method != reqwest::Method::GET {
                    tracing::info!(
                        method = %method,
                        url = %url_str,
                        "Dry-run: intercepted non-GET request in fetch_all"
                    );
                    let mock_body = serde_json::to_vec(&serde_json::json!({
                        "__dry_run__": true,
                        "intercepted_method": method.as_str(),
                        "intercepted_url": url_str,
                    }))
                    .unwrap_or_default();
                    return Ok(wit_http::Response {
                        status: 200,
                        headers: vec![("x-talos-dry-run".to_string(), "true".to_string())],
                        body: mock_body,
                    });
                }

                let client = self_http_client.clone();

                let method_str_for_audit = method.as_str().to_string();
                let mut builder = client
                    .request(method, &url_str)
                    .timeout(std::time::Duration::from_millis(timeout_ms));
                for (name, value) in &headers {
                    builder = builder.header(name.as_str(), value.as_str());
                }
                if !body.is_empty() {
                    builder = builder.body(body);
                }

                let response = builder.send().await.map_err(|e| {
                    if e.is_timeout() {
                        wit_http::Error::Timeout
                    } else {
                        wit_http::Error::Networkerror
                    }
                })?;

                let status = response.status().as_u16();
                // Audit log: log host + path only (never full URL — query params may contain secrets)
                if let Ok(parsed_url) = url::Url::parse(&url_str) {
                    tracing::info!(
                        method = %method_str_for_audit,
                        host = %parsed_url.host_str().unwrap_or("unknown"),
                        path = %parsed_url.path(),
                        status = status,
                        "HTTP audit"
                    );
                }
                // MCP-1114: cap inbound header count + per-value size.
                // Sibling of the wit_http::fetch single-call site.
                if response.headers().len() > MAX_INBOUND_HEADERS {
                    tracing::warn!(
                        header_count = response.headers().len(),
                        limit = MAX_INBOUND_HEADERS,
                        "wit_http::fetch_all response rejected: header count exceeds cap"
                    );
                    return Err(wit_http::Error::Networkerror);
                }
                let resp_headers: Vec<(String, String)> = {
                    let mut out: Vec<(String, String)> =
                        Vec::with_capacity(response.headers().len());
                    for (k, v) in response.headers().iter() {
                        if v.as_bytes().len() > MAX_INBOUND_HEADER_VALUE_BYTES {
                            tracing::warn!(
                                header = %k,
                                value_len = v.as_bytes().len(),
                                limit = MAX_INBOUND_HEADER_VALUE_BYTES,
                                "wit_http::fetch_all response rejected: header value exceeds cap"
                            );
                            return Err(wit_http::Error::Networkerror);
                        }
                        out.push((
                            k.to_string(),
                            String::from_utf8_lossy(v.as_bytes()).into_owned(),
                        ));
                    }
                    out
                };

                let mut resp_body_bytes = Vec::new();
                let mut stream = response.bytes_stream();
                use futures_util::StreamExt;
                while let Some(chunk_result) = stream.next().await {
                    let chunk = chunk_result.map_err(|_| wit_http::Error::Networkerror)?;
                    if resp_body_bytes.len() + chunk.len() > max_r {
                        return Err(wit_http::Error::Networkerror);
                    }
                    resp_body_bytes.extend_from_slice(&chunk);
                }

                        Ok(wit_http::Response {
                            status,
                            headers: resp_headers,
                            body: resp_body_bytes,
                        })
                    }
                    .await;
                    (idx, result)
                }
            }));

        let mut indexed: Vec<(usize, Result<wit_http::Response, wit_http::Error>)> =
            stream.buffer_unordered(concurrency_limit).collect().await;
        // Restore the documented input order (see the tagging comment
        // above) — completion order is an implementation detail.
        indexed.sort_unstable_by_key(|&(i, _)| i);
        // Per-failure diagnostics for DISPATCH failures. Validation
        // failures (request_hosts[i] == None) were already diagnosed at
        // validation time; capped globally by HOST_DIAG_CAP.
        let tier1 = self.max_llm_tier == talos_workflow_job_protocol::LlmTier::Tier1;
        for (idx, r) in &indexed {
            if let Err(e) = r {
                if let Some(Some(host)) = request_hosts.get(*idx) {
                    // A Networkerror under a Tier-1 actor is almost always the
                    // local-egress-only gate (same reasoning as the single-fetch
                    // path); surface the actionable reason instead of the
                    // ambiguous connection/reset class.
                    if tier1 && matches!(e, wit_http::Error::Networkerror) {
                        self.emit_host_diagnostic(
                            "tier1-egress-blocked",
                            &format!(
                                "fetch_all[{idx}]: '{host}' blocked by this workflow's Tier-1 \
                                 actor (local-egress-only). Bind a Tier-2 actor to reach \
                                 external APIs."
                            ),
                        )
                        .await;
                        continue;
                    }
                    let class = match e {
                        wit_http::Error::Timeout => "timed out",
                        _ => "failed (connection/reset or response over limits)",
                    };
                    self.emit_host_diagnostic(
                        "batch-request-failed",
                        &format!("fetch_all[{idx}] to '{host}' {class}"),
                    )
                    .await;
                }
            }
        }
        indexed.into_iter().map(|(_, r)| r).collect()
    }

    /// Tier 1 — Fetch with secret injected as `Authorization: Bearer {value}`.
    ///
    /// Resolves `slot` via the SecretProvider and prepends the Authorization header
    /// to `req` before dispatching through the standard `fetch` path (which applies
    /// all security checks: host allowlist, SSRF protection, method allowlist,
    /// rate limiting). The secret value never enters guest memory.
    async fn fetch_with_bearer(
        &mut self,
        slot: u64,
        mut req: wit_http::Request,
    ) -> Result<wit_http::Response, wit_http::Error> {
        // Resolve the slot to its plaintext value on the host side only.
        let auth_value = self
            .provider
            .into_auth_header(talos_secrets::SlotHandle(slot), "Authorization")
            .map_err(|e| {
                tracing::warn!(slot, error = %e, "fetch-with-bearer: slot lookup failed");
                wit_http::Error::Networkerror
            })?;
        // `into_auth_header` ALREADY applies the case-insensitive "Bearer " scheme
        // prefix when the header name is "Authorization" (and is idempotent — it
        // won't double up if the secret already carries a Bearer/Basic scheme). Use
        // the returned value verbatim. A second manual "Bearer " here produced
        // `Authorization: Bearer Bearer <token>`, which every upstream rejects with
        // 401 (first observed against api.github.com via the github-pr-reviewer
        // module — the first end-to-end fetch_with_bearer exercise in the stack).
        // L-4: copy out of the Zeroizing buffer, then drop it so the plaintext is
        // wiped; the owned String is moved into req.headers (one copy in flight).
        let header = auth_value.as_str().to_string();
        drop(auth_value);
        req.headers.insert(0, ("Authorization".to_string(), header));
        // Dispatch through the standard fetch path; all security checks apply.
        self.fetch(req).await
    }

    /// Tier 1 — Fetch with secret injected as a named header.
    ///
    /// Resolves `slot` via the SecretProvider and prepends `header-name: {value}`
    /// to `req` before dispatching through the standard `fetch` path. Use for
    /// API-key schemes such as `x-api-key` (Anthropic) or `x-goog-api-key` (Gemini).
    /// The secret value never enters guest memory.
    async fn fetch_with_header(
        &mut self,
        slot: u64,
        header_name: String,
        mut req: wit_http::Request,
    ) -> Result<wit_http::Response, wit_http::Error> {
        let header_value = self
            .provider
            .into_auth_header(talos_secrets::SlotHandle(slot), &header_name)
            .map_err(|e| {
                tracing::warn!(slot, header_name, error = %e, "fetch-with-header: slot lookup failed");
                wit_http::Error::Networkerror
            })?;
        // L-4: Zeroizing<String> → owned String at point of use; the
        // wrapper wipes when its scope ends.
        let owned_value = (*header_value).clone();
        drop(header_value);
        req.headers.insert(0, (header_name, owned_value));
        self.fetch(req).await
    }
}

#[cfg(test)]
mod write_ceiling_http_tests {
    use super::*;

    #[test]
    fn get_is_a_read() {
        assert!(!http_method_mutates(&wit_http::Method::Get));
    }

    #[test]
    fn write_verbs_mutate() {
        for m in [
            wit_http::Method::Post,
            wit_http::Method::Put,
            wit_http::Method::Patch,
            wit_http::Method::Delete,
        ] {
            assert!(http_method_mutates(&m), "{m:?} must be a mutation");
        }
    }
}
