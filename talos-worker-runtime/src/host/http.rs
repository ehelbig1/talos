//! `http` host interface (fetch / fetch-all with host allowlists,
//! SSRF gates, vault:// header resolution and response caps).

use super::*;

use crate::reason_class;
pub(crate) use talos_idempotency::dedup_request_hash;
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

/// Namespace an engine-stamped idempotency key by the job's TENANCY principal
/// before it touches the process-global store.
///
/// The store is shared by every execution on this worker, and the literal
/// `idempotency_key` is caller-authored node config. Keyed on the literal
/// alone (the pre-2026-09 shape) two tenants using the same literal — or two
/// unrelated workflows of ONE tenant — were served each other's cached 2xx
/// response. The key is now `{user_id}:{actor_id|-}:{host}:{key}`, all four
/// taken from the SIGNED `JobRequest` fields already on `TalosContext` (never
/// from guest args), so a collision needs the same user, actor and host.
///
/// Returns `None` when the context carries no `user_id`: with no tenancy
/// principal there is no namespace to scope to, and the safe direction is to
/// not engage the store at all (the `Idempotency-Key` header remains the
/// primary dedup mechanism) rather than share a `-:-:…` bucket across every
/// principal-less execution on the worker.
pub(crate) fn scoped_dedup_key(
    user_id: Option<uuid::Uuid>,
    actor_id: Option<uuid::Uuid>,
    host: &str,
    key: &str,
) -> Option<String> {
    let user = user_id?;
    let actor = actor_id.map_or_else(|| "-".to_string(), |a| a.to_string());
    Some(format!(
        "{user}:{actor}:{}:{key}",
        host.to_ascii_lowercase()
    ))
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

/// Latch `class` against the `forbiddenhost` discriminant and return it.
///
/// The one place a `wit_http` POLICY or CAP denial becomes a WIT error. It
/// exists so the class and the discriminant are chosen in the SAME expression:
/// the marker is only ever stamped onto a guest error that carries the token
/// the class was paired with (see
/// [`crate::runtime::last_network_reason_suffix`]), so a pairing built
/// anywhere other than the `return Err(...)` is a pairing that can silently go
/// wrong. Latch-only by design — these sites already publish their operator
/// diagnostic through `record_capability_denied`, and the pure caps
/// deliberately publish none.
///
/// `&TalosContext` (not `&mut`) so the `fetch_all` validation loop, which
/// holds an immutable borrow of the request vector, can call it inline.
fn deny_forbidden(ctx: &TalosContext, class: &'static str) -> wit_http::Error {
    ctx.record_http_denial(class, reason_class::WIT_FORBIDDENHOST);
    wit_http::Error::Forbiddenhost
}

/// Latch `class` against the `invalidurl` discriminant and return it.
/// Sibling of [`deny_forbidden`]; see its doc for why the pairing lives here.
fn deny_invalid_url(ctx: &TalosContext, class: &'static str) -> wit_http::Error {
    ctx.record_http_denial(class, reason_class::WIT_INVALIDURL);
    wit_http::Error::Invalidurl
}

/// Re-export of the shared policy→class mapper. It moved to
/// [`crate::reason_class::tier1_egress_class`] when `graphql`, `webhook` and
/// `http_stream` grew the same denial — all four surfaces call the same
/// `tier1_egress_deny_reason`, so a per-file copy of the mapping is exactly
/// the drift this workspace keeps paying for.
use crate::reason_class::tier1_egress_class;

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
            return Err(deny_forbidden(self, reason_class::CAPABILITY_WORLD));
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
            return Err(deny_invalid_url(self, reason_class::URL_TOO_LONG));
        }
        // Validate and parse the URL first.
        let url: url::Url = match req.url.parse() {
            Ok(u) => u,
            // A genuine author typo — the ONE `invalidurl` cause that is not a
            // host decision. Telling it apart from the byte cap above and the
            // plaintext-scheme SECURITY refusal below is the point of the class:
            // all three reach the operator as `name: "invalidurl"`.
            Err(_) => return Err(deny_invalid_url(self, reason_class::URL_PARSE)),
        };

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
                return Err(deny_invalid_url(self, reason_class::INSECURE_SCHEME));
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
            return Err(deny_forbidden(self, reason_class::NO_ALLOWLIST));
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
            return Err(deny_forbidden(self, reason_class::PRIVATE_IP));
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
                return Err(deny_forbidden(self, reason_class::ALLOWED_HOSTS));
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
                return Err(deny_forbidden(self, tier1_egress_class(policy)));
            }
        }

        // Write-ceiling gate: a read-only actor may issue read requests (GET)
        // but not mutating ones (POST / PUT / PATCH / DELETE). Pure decision,
        // in the cheap-validation block before the rate-limit charge. Inert
        // unless `TALOS_WRITE_CEILING_ENFORCED=1`.
        if http_method_mutates(&req.method)
            && self.write_ceiling_refuses("http-fetch", host).await
        {
            return Err(deny_forbidden(self, reason_class::WRITE_CEILING));
        }
        // Strict-egress gate for the READ side: a GET URL is guest-
        // influenceable outbound data (exfil channel), so with
        // `TALOS_WRITE_CEILING_STRICT_EGRESS=1` a read-only actor may
        // read only from operator-NAMED hosts — wildcard admissions are
        // refused. Inert unless both ceiling flags are on.
        if !http_method_mutates(&req.method)
            && self.read_egress_refuses("http-fetch", host, host_match).await
        {
            return Err(deny_forbidden(self, reason_class::WRITE_CEILING_STRICT_EGRESS));
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
            return Err(deny_forbidden(self, reason_class::EXECUTION_RATE_LIMIT));
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
            return Err(deny_forbidden(self, reason_class::PER_HOST_RATE_LIMIT));
        }
        if self.is_cancelled() {
            tracing::info!(module_id = ?self.module_id, "Execution cancelled");
            if let Some(ref m) = self.metrics {
                m.record_execution_cancelled();
            }
            self.emit_network_failure(
                reason_class::CANCELLED,
                reason_class::WIT_NETWORKERROR,
                "the execution was cancelled before the request was sent",
            )
            .await;
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

        // ── Opt-in idempotency: header decision + worker-side dedup ─────────
        // Hoisted ABOVE the DNS lookup / breaker / vault-resolve (2026-09):
        // every input here is pure — the verb, the raw header names, the URL,
        // the body and the SIGNED tenancy fields — so a cached hit pays no
        // DNS and strands no breaker permit, and a key-reuse refusal is
        // decided before any I/O. Dry-run stays ahead of it so a dry-run POST
        // is still mocked rather than served from the store.
        let method_str_early = match req.method {
            wit_http::Method::Get => "GET",
            wit_http::Method::Post => "POST",
            wit_http::Method::Put => "PUT",
            wit_http::Method::Delete => "DELETE",
            wit_http::Method::Patch => "PATCH",
        };
        // The key goes out as a header only on MUTATING verbs (a GET is safe to
        // retry) and only when the guest has not set the header itself.
        let idem_header_to_emit: Option<String> = if http_method_mutates(&req.method) {
            let guest_set = req
                .headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case("idempotency-key"));
            self.idempotency_key.clone().filter(|_| !guest_set)
        } else {
            None
        };
        // The worker-side store engages only for the header-emitting case and
        // only under a tenancy principal (`scoped_dedup_key`); the hash binds
        // the record to THIS request's method + URL + body.
        let dedup_key: Option<String> = idem_header_to_emit
            .as_deref()
            .and_then(|idem| scoped_dedup_key(self.user_id, self.actor_id, host, idem));
        let request_hash = dedup_request_hash(method_str_early, &req.url, &req.body);
        if let Some(ref k) = dedup_key {
            match get_global_idempotency_store().check(k, &request_hash) {
                DedupCheck::Completed(cached) => {
                    tracing::info!(
                        host,
                        "idempotent send short-circuited: returning cached response for a \
                         previously-completed idempotency key (worker-side dedup)"
                    );
                    // `return` resolves the enclosing `async move` block — NOT the
                    // outer fn — so metrics are still recorded once at the tail.
                    self.consume_async_fuel(async_start.elapsed(), "http::fetch");
                    return Ok(wit_http::Response {
                        status: cached.status,
                        headers: cached.headers,
                        body: cached.body,
                    });
                }
                DedupCheck::Mismatch => {
                    // Same key, DIFFERENT request. Serving the cached response
                    // would hand this request another request's body; firing
                    // it would double-send under a key the destination has
                    // already honoured. Refuse. No `reason_class` token is
                    // minted for this: `reason_class::ALL` is a CLOSED set
                    // pinned cross-crate by `talos-reason-class`'s
                    // `closed_set_snapshot`, and a bare `forbiddenhost` is
                    // already non-transient in every downstream classifier —
                    // so the latch is CLEARED (the totality rule: every
                    // failing return decides it) and the cause travels on the
                    // audit ledger + `[host:…]` diagnostic instead.
                    self.record_capability_denied("http-fetch", "idempotency-key-reuse", host)
                        .await;
                    tracing::warn!(
                        host,
                        module_id = ?self.module_id,
                        "idempotency key reused for a different request (method/url/body \
                         differ from the completed send) — refusing rather than replaying"
                    );
                    self.record_network_outcome(None);
                    self.consume_async_fuel(async_start.elapsed(), "http::fetch");
                    return Err(wit_http::Error::Forbiddenhost);
                }
                DedupCheck::Proceed => {}
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
                            return Err(deny_forbidden(self, reason_class::PRIVATE_IP));
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
                    self.emit_network_failure(
                        reason_class::DNS,
                        reason_class::WIT_NETWORKERROR,
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
            return Err(deny_forbidden(self, reason_class::METHOD_ALLOWLIST));
        }

        // Check circuit breaker before making request
        let host_str = host.to_string();
        // ── The permit, and why the admission is not a bool ─────────────────
        //
        // `begin_request` returns an RAII `RequestPermit`. Admission on a
        // HALF-OPEN circuit spends one of that host's three trial tokens, and
        // the permit is the obligation to account for it. Everything between
        // here and `builder.send()` below can exit without reaching the
        // settle — three statement exits (the header cap, the body cap, the
        // `?` on `resolve_vault_header`; the idempotency dedup's
        // `return Ok(cached)` was a fourth until it was hoisted ahead of the
        // DNS lookup in 2026-09), two `.await` points at which the whole future
        // can be DROPPED (execution timeout, worker shutdown, a sibling
        // failing a fan-out), and a panic unwinding through any of it. The
        // `?` and the cancellation are the two that no per-`return` patch can
        // cover, and they are the two that actually fired: an unresolvable
        // `vault://oauth/...` header is deterministic on exactly the header
        // shape the calendar nodes use.
        //
        // Pre-permit, each of those spent a token and repaid nothing, and
        // `HalfOpen` has NO time bound — it is left only by concluding
        // `test_requests` trials. A host that leaked all three sat at
        // half-open-with-zero-tokens for the life of the process, refusing
        // every later request as `half_open_exhausted`. That is what took
        // `www.googleapis.com` out from 2026-08-11 11:35 until the 23:06
        // container recreate.
        //
        // Dropping the permit without settling repays the token and records
        // NEITHER outcome — see `RequestPermit` for why "the trial did not
        // conclude" is a third state and why recording a synthetic success or
        // failure instead would each be a distinct bug.
        //
        // `fetch_all` takes ONE permit per distinct host in the batch (see its
        // admission pass) and settles each after the join.
        let Some(mut permit) = get_global_circuit_breaker().begin_request(&host_str) else {
            tracing::warn!(host = %host, "Circuit breaker open - rejecting HTTP request");
            self.emit_network_failure(
                reason_class::CIRCUIT_OPEN,
                reason_class::WIT_NETWORKERROR,
                &format!(
                    "circuit breaker open for '{host}' after recent failures — \
                     request rejected without being sent; it closes automatically"
                ),
            )
            .await;
            return Err(wit_http::Error::Networkerror);
        };

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
            return Err(deny_forbidden(self, reason_class::REQUEST_HEADER_CAP));
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
            return Err(deny_forbidden(self, reason_class::REQUEST_BODY_CAP));
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
            let resolved = match self
                .resolve_vault_header(name.as_str(), value.as_str())
                .await
            {
                Ok(v) => v,
                // Leaves the circuit-breaker permit unsettled on the way out,
                // exactly as the `?` it replaces did — see the permit doc above.
                Err(_) => return Err(deny_forbidden(self, reason_class::SECRET_LOOKUP)),
            };
            builder = builder.header(name.as_str(), resolved.as_ref());
        }
        // Opt-in idempotency (Task 3): emit the engine-stamped key as the
        // industry-standard `Idempotency-Key` header on MUTATING requests so a
        // retried send is deduplicated at the destination (Stripe-style). The
        // decision (mutating verb, guest did not set its own header) was made
        // ABOVE, before DNS, alongside the worker-side dedup check.
        if let Some(ref idem) = idem_header_to_emit {
            builder = builder.header("Idempotency-Key", idem.as_str());
        }
        if !body.is_empty() {
            builder = builder.body(body.clone());
        }

        let response = match builder.send().await {
            Ok(resp) => {
                // Settled with the STATUS, not merely with "the transport
                // worked". On a Closed circuit that is identical to the
                // previous `record_success` — a status can never open a
                // circuit, because this breaker is host-keyed and
                // process-global and a 401 belongs to one user's credential.
                // On a HALF-OPEN trial a 5xx — and ONLY a 5xx — now fails the
                // trial instead of closing the circuit against a host that is
                // answering nothing but errors. A 429 deliberately PASSES the
                // trial: it is per-caller (`userRateLimitExceeded`), so
                // failing a trial on it turns one tenant's routine quota error
                // into every tenant's outage. Full argument, including the
                // residual cross-tenant tail it accepts, in
                // `circuit_breaker.rs`.
                permit.settle_response(resp.status().as_u16());
                // Clear the reason latch: the module's most recent HTTP
                // outcome is a success, so a class recorded by an earlier,
                // recovered failure must not be attributed to whatever this
                // module fails on later.
                self.record_network_outcome(None);
                resp
            }
            Err(e) => {
                if e.is_builder() {
                    // The request was never constructed, so it never left the
                    // process and nothing was learned about the host. On this
                    // path that means a header name or value the GUEST wrote
                    // that `http::HeaderName`/`HeaderValue` refused —
                    // `RequestBuilder::header` stores the error and surfaces
                    // it here at `send()`. Feeding it to `record_failure`
                    // (the pre-2026-08-12 behaviour) let a module open a
                    // shared, process-global circuit for a healthy host with
                    // five malformed-header fetches and zero packets. The
                    // guest-visible error and the reason class below are
                    // unchanged; only the breaker's accounting is.
                    permit.settle_no_evidence();
                } else {
                    permit.settle_transport_failure();
                }
                // D3 — the ONE place the real transport error is surfaced.
                // Worker log only (never host→guest, never a stored payload):
                // URL erased, DLP-redacted, then IP/path-sanitized. Before
                // this, `e` was consumed for two booleans and dropped, so the
                // connect/TLS/reset path logged NOTHING AT ALL and the true
                // cause of a `networkerror` was unrecoverable after the fact.
                // Bounded: one line per failed HTTP call, and gated on the
                // SAME per-execution `HOST_DIAG_CAP` (100) the diagnostic
                // channel spends — otherwise this would be a second, uncapped
                // stream bounded only by MAX_HTTP_CALLS_PER_EXECUTION (1000)
                // × the sanitizer's 2000-char truncation.
                if self.host_diag_budget_remaining() {
                    tracing::warn!(
                        module_id = ?self.module_id,
                        host = %host_str,
                        detail = %reason_class::sanitized_transport_detail(&e),
                        "outbound HTTP request failed (sanitized transport detail)"
                    );
                }
                if e.is_timeout() {
                    self.emit_network_failure(
                        reason_class::TIMEOUT,
                        reason_class::WIT_TIMEOUT,
                        &format!("request to '{host_str}' timed out"),
                    )
                    .await;
                    return Err(wit_http::Error::Timeout);
                }
                // Classify FIRST, then decide whether the Tier-1 explanation
                // applies. Pre-fix this branch keyed on the bare
                // `is_connect()`, which is also true for TLS handshake
                // failures — so a genuine certificate problem under a Tier-1
                // actor was reported as an egress-policy deny, sending the
                // operator to change the actor's tier over a broken cert.
                let class = reason_class::classify_reqwest_send_error(&e);
                // The gate keys on `local_egress_only` — the value the
                // resolver in THIS context's `http_client` was actually built
                // with — never on `max_llm_tier == Tier1`. Since the
                // 2026-07-23 `egress_scope` split the two disagree in both
                // directions, and both mistakes are load-bearing now that the
                // class drives retry classification:
                //   * `Tier1 + egress_scope=Public` (the house pattern for a
                //     Gmail-reading privacy actor) permits public egress, so a
                //     connect failure there is an ORDINARY transport failure.
                //     Tagging it `tier1-egress` makes it `capability_denied`
                //     and vetoes exactly the retries D1 restores — the whole
                //     defect, re-introduced for the flagship actor shape.
                //   * `Tier2 + egress_scope=Local` denies public egress, so
                //     its connect failures ARE the gate and must not retry;
                //     keying on the tier left them classed `connect-failed`
                //     (transient) and retried against a deny that cannot
                //     change between attempts.
                if reason_class::is_local_egress_attributable(class, self.local_egress_only) {
                    // A local-egress-only actor's SsrfFilteringResolver drops
                    // every public IP, leaving hyper an EMPTY address list —
                    // which surfaces as `tcp connect error: Network
                    // unreachable`, i.e. exactly this class. So a connect
                    // failure to a non-loopback host is almost always the
                    // data-egress gate, NOT the host being down. Say so with
                    // the fix, since the resolver itself (a reqwest
                    // dns::Resolve impl) has no TalosContext to emit from.
                    // Loopback/private targets still connect under
                    // local-egress-only (local Ollama), so those failures
                    // produce the generic reason below.
                    self.emit_network_failure(
                        reason_class::TIER1_EGRESS,
                        reason_class::WIT_NETWORKERROR,
                        &format!(
                            "'{host_str}' was blocked by this workflow's actor \
                             (local-egress-only — data must not leave the host). To reach \
                             an external API, set the actor's egress_scope to 'public' \
                             (set_actor_egress_scope) or bind a Tier-2 actor."
                        ),
                    )
                    .await;
                    return Err(wit_http::Error::Networkerror);
                }
                // Fixed prose per class — never the reqwest string, which
                // embeds the full URL (query params included) and can carry
                // proxy / internal-infra detail.
                let prose = match class {
                    reason_class::TLS => "the TLS handshake failed (certificate or protocol)",
                    reason_class::CONNECT_REFUSED => "the peer refused the connection",
                    reason_class::CONNECT_FAILED => {
                        "the connection could not be established (unreachable or no route)"
                    }
                    _ => "the request failed after connecting (reset or protocol error)",
                };
                self.emit_network_failure(class, reason_class::WIT_NETWORKERROR, &format!("request to '{host_str}': {prose}"))
                    .await;
                return Err(wit_http::Error::Networkerror);
            }
        };

        let status = response.status().as_u16();
        // Host + path LENGTH only: capability tokens and presigned keys live
        // in paths, and the audit line lands in shared log storage.
        tracing::info!(
            method = %method_str_for_audit,
            host = %url.host_str().unwrap_or("unknown"),
            path_len = url.path().len(),
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
            self.emit_network_failure(
                reason_class::HEADER_CAP,
                reason_class::WIT_NETWORKERROR,
                &format!(
                    "the response from '{host_str}' carried more headers than the \
                     inbound cap ({MAX_INBOUND_HEADERS}) allows"
                ),
            )
            .await;
            return Err(wit_http::Error::Networkerror);
        }
        // Two-pass so the oversize-header diagnostic can be emitted after the
        // borrow of `response.headers()` ends — `emit_network_failure` takes
        // `&mut self` and the loop below holds no `self` borrow, but keeping
        // the await out of the iteration also bounds it to one emit per call.
        let mut oversize_header: Option<String> = None;
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
                    // Header NAME only — the oversized VALUE is upstream
                    // content and may be a token; it never leaves the host.
                    oversize_header = Some(k.to_string());
                    break;
                }
                out.push((
                    k.to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                ));
            }
            out
        };
        if let Some(name) = oversize_header {
            self.emit_network_failure(
                reason_class::HEADER_CAP,
                reason_class::WIT_NETWORKERROR,
                &format!(
                    "the response from '{host_str}' carried a '{name}' header larger \
                     than the inbound cap ({MAX_INBOUND_HEADER_VALUE_BYTES} bytes)"
                ),
            )
            .await;
            return Err(wit_http::Error::Networkerror);
        }
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
            let chunk = match chunk_result {
                Ok(c) => c,
                Err(e) => {
                    // Same D3 treatment as the send path: the raw error is
                    // logged sanitized host-side and never crosses to the
                    // guest. One line per failed body read, under the same
                    // per-execution HOST_DIAG_CAP budget.
                    if self.host_diag_budget_remaining() {
                        tracing::warn!(
                            module_id = ?self.module_id,
                            host = %host_str,
                            detail = %reason_class::sanitized_transport_detail(&e),
                            "HTTP response body stream failed (sanitized transport detail)"
                        );
                    }
                    self.emit_network_failure(
                        reason_class::RESPONSE_STREAM,
                        reason_class::WIT_NETWORKERROR,
                        &format!(
                            "the response body from '{host_str}' failed mid-transfer \
                             (transport reset or decode error)"
                        ),
                    )
                    .await;
                    return Err(wit_http::Error::Networkerror);
                }
            };
            if resp_body_bytes.len() + chunk.len() > max_resp {
                tracing::warn!(
                    limit = max_resp,
                    "HTTP response exceeds size limit during streaming"
                );
                self.emit_network_failure(
                    reason_class::RESPONSE_TOO_LARGE,
                    reason_class::WIT_NETWORKERROR,
                    &format!(
                        "the response body from '{host_str}' exceeded the {max_resp}-byte \
                         limit (WASM_HTTP_MAX_RESPONSE_BYTES) and was not delivered"
                    ),
                )
                .await;
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
                    &request_hash,
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
        // Sibling parity with `fetch`'s cancel guard ~650 lines above, and the
        // parity is LOAD-BEARING, not cosmetic. A bare `networkerror` carrying
        // no `[reason_class=…]` marker is classified `network_transient` by
        // BOTH transient gates — `runtime::is_transient_error_text` in-worker
        // and `talos_retry_intelligence::classify_error` on the controller — so
        // a cancelled BATCH fetch was RE-DISPATCHED, onto a fresh
        // `TalosContext` whose `cancelled` flag is false. The cancel did not
        // stick. Both gates already carry a `reason_class=cancelled` arm
        // hoisted ABOVE their `networkerror` arm for exactly this reason (see
        // `crate::reason_class::NON_TRANSIENT`); this site simply never
        // stamped the marker while its single-request sibling did.
        if self.is_cancelled() {
            tracing::info!(module_id = ?self.module_id, "Execution cancelled");
            if let Some(ref m) = self.metrics {
                m.record_execution_cancelled();
            }
            self.emit_network_failure(
                reason_class::CANCELLED,
                reason_class::WIT_NETWORKERROR,
                "the execution was cancelled before the batch request was sent",
            )
            .await;
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
            self.record_http_denial(
                reason_class::CAPABILITY_WORLD,
                reason_class::WIT_FORBIDDENHOST,
            );
            return reqs
                .iter()
                .map(|_| Err(wit_http::Error::Forbiddenhost))
                .collect();
        }

        // ── Batch-size cap against the REMAINING per-execution budget ────────
        // `reqs.len()` is guest-controlled and was unbounded: the per-entry
        // validation loop below does a URL parse, an allowlist match, a DNS
        // lookup and a vault resolve for EVERY entry before the budget was
        // consulted, so a 100 000-entry batch paid all of that work and was
        // only then refused (MCP-783 moved the charge AFTER validation to stop
        // denied entries burning budget — correct, but it left the validation
        // work itself unbounded). Refuse up front when the batch could not fit
        // in what is left of `MAX_HTTP_CALLS_PER_EXECUTION`: nothing is
        // validated, nothing is resolved, nothing is charged.
        let remaining_budget = MAX_HTTP_CALLS_PER_EXECUTION.saturating_sub(
            self.http_call_count
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        if reqs.len() as u64 > remaining_budget {
            tracing::warn!(
                module_id = ?self.module_id,
                batch = reqs.len(),
                remaining = remaining_budget,
                limit = MAX_HTTP_CALLS_PER_EXECUTION,
                "fetch_all: batch exceeds the remaining per-execution HTTP call budget — refused up front"
            );
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("http");
            }
            self.record_http_denial(
                reason_class::EXECUTION_RATE_LIMIT,
                reason_class::WIT_FORBIDDENHOST,
            );
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

        // Set when an entry observed cancellation during validation; latched
        // ONCE after the loop so the batch's class is `cancelled` (the
        // non-transient arm both retry gates carry) rather than a bare
        // `networkerror` a redispatch would treat as transient.
        let mut cancelled_during_validation = false;

        for req in &reqs {
            // Per-ENTRY cancellation. The entry check at the top of this fn
            // covered only the first entry: a cancel arriving while entry 1's
            // DNS lookup or vault resolve was in flight let entries 2..N keep
            // resolving and then go out on the wire. Cheap (one atomic load).
            if self.is_cancelled() {
                cancelled_during_validation = true;
                validated.push(Err(wit_http::Error::Networkerror));
                continue;
            }
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
                validated.push(Err(deny_forbidden(self, reason_class::REQUEST_BODY_CAP)));
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
                validated.push(Err(deny_invalid_url(self, reason_class::URL_TOO_LONG)));
                continue;
            }

            // 1. URL parse.
            let url: url::Url = match req.url.parse() {
                Ok(u) => u,
                Err(_) => {
                    validated.push(Err(deny_invalid_url(self, reason_class::URL_PARSE)));
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
                    validated.push(Err(deny_invalid_url(self, reason_class::INSECURE_SCHEME)));
                    continue;
                }
            }

            // 2. Allowlist must be configured.
            if self.allowed_hosts.is_empty() {
                self.record_capability_denied("http-fetch-all", "no-allowlist-configured", &host)
                    .await;
                validated.push(Err(deny_forbidden(self, reason_class::NO_ALLOWLIST)));
                continue;
            }

            // 3. SSRF: classify IP literals (no network I/O).
            //    Single source of truth in classify_private_ip — covers
            //    CGNAT and IPv4-mapped IPv6 too.
            if let Some((ip, policy)) = denied_ip_literal(&url) {
                self.record_capability_denied("http-fetch-all", policy, &ip.to_string())
                    .await;
                validated.push(Err(deny_forbidden(self, reason_class::PRIVATE_IP)));
                continue;
            }

            // 4. allowed_hosts pattern match.
            let host_match = match host_allowlist_match_kind(&self.allowed_hosts, &host) {
                Some(kind) => kind,
                None => {
                    self.record_capability_denied("http-fetch-all", "allowed-hosts", &host)
                        .await;
                    validated.push(Err(deny_forbidden(self, reason_class::ALLOWED_HOSTS)));
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
                    validated.push(Err(deny_forbidden(self, tier1_egress_class(policy))));
                    continue;
                }
            }

            // 5b. Write-ceiling gate: read-only actors may GET but not
            //     mutate. Per-request so a mixed batch rejects only the
            //     mutating entries. Inert unless enforcement is on.
            if http_method_mutates(&req.method)
                && self.write_ceiling_refuses("http-fetch-all", &host).await
            {
                validated.push(Err(deny_forbidden(self, reason_class::WRITE_CEILING)));
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
                validated.push(Err(deny_forbidden(
                    self,
                    reason_class::WRITE_CEILING_STRICT_EGRESS,
                )));
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
                validated.push(Err(deny_forbidden(self, reason_class::METHOD_ALLOWLIST)));
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
                validated.push(Err(deny_forbidden(self, reason_class::PER_HOST_RATE_LIMIT)));
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
                            validated.push(Err(deny_forbidden(self, reason_class::PRIVATE_IP)));
                            continue;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            host = %host,
                            error = %e,
                            "fetch_all: DNS resolution failed for SSRF check"
                        );
                        // Latch DNS, paired with the discriminant this arm
                        // returns. Two reasons, and the second is the one that
                        // matters. (a) Diagnostic: the single-fetch twin
                        // already says `dns`. (b) SAFETY: `networkerror` is
                        // the discriminant `wit_graphql`'s denials are now
                        // paired with, so an UNLATCHED `networkerror` here
                        // would be a message a stale graphql capability
                        // denial could be stamped onto — turning a genuine,
                        // retryable DNS blip into a non-transient
                        // `capability_denied`. Writing the class is what makes
                        // the latch describe THIS call. `dns` is transient, so
                        // the reading is unchanged from the bare token.
                        self.record_network_outcome(Some(reason_class::Reason::network(
                            reason_class::DNS,
                        )));
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
                validated.push(Err(deny_forbidden(self, reason_class::REQUEST_HEADER_CAP)));
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
                validated.push(Err(deny_forbidden(self, reason_class::SECRET_LOOKUP)));
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
        if cancelled_during_validation {
            if let Some(ref m) = self.metrics {
                m.record_execution_cancelled();
            }
            self.emit_network_failure(
                reason_class::CANCELLED,
                reason_class::WIT_NETWORKERROR,
                "the execution was cancelled while the batch was being validated; \
                 entries not yet validated were not sent",
            )
            .await;
        }

        // ── Circuit-breaker admission: per BATCH, per HOST ───────────────────
        // Until 2026-09 this path took no permit at all (see the long note at
        // the `send()` below for the history). The shape argued for there is
        // the one implemented here: ONE `begin_request` per DISTINCT host in
        // the batch, one settled permit per distinct host after the join. Per
        // ENTRY admission was rejected on measurement (a 10-wide batch against
        // a dead host would trip a 5-consecutive-failure breaker inside one
        // guest call and spend all three half-open trial tokens at once).
        //
        // Refused hosts convert their entries to `Networkerror` HERE, before
        // the budget charge, so a refused entry costs no budget (the MCP-783
        // rule). The permits are settled after the join with the WORST outcome
        // seen for that host — a transport failure beats a status, a 5xx beats
        // a 2xx — so a batch is one trial, not N.
        let breaker = get_global_circuit_breaker();
        let mut host_permits: std::collections::HashMap<
            String,
            crate::circuit_breaker::RequestPermit<'static>,
        > = std::collections::HashMap::new();
        let mut breaker_refused: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        // Host per input slot — used for admission now and for the settle +
        // per-failure diagnostics after the join. `None` = the entry failed
        // validation (already diagnosed at validation time).
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
        for (v, host) in validated.iter_mut().zip(request_hosts.iter()) {
            let Some(host) = host else { continue };
            if v.is_err() {
                continue;
            }
            if !host_permits.contains_key(host) && !breaker_refused.contains(host) {
                match breaker.begin_request(host) {
                    Some(permit) => {
                        host_permits.insert(host.clone(), permit);
                    }
                    None => {
                        breaker_refused.insert(host.clone());
                    }
                }
            }
            if breaker_refused.contains(host) {
                *v = Err(wit_http::Error::Networkerror);
            }
        }
        for host in &breaker_refused {
            tracing::warn!(host = %host, "fetch_all: circuit breaker open — entries to this host refused");
            self.emit_network_failure(
                reason_class::CIRCUIT_OPEN,
                reason_class::WIT_NETWORKERROR,
                &format!(
                    "circuit breaker open for '{host}' after recent failures — \
                     the batch entries to it were rejected without being sent; it closes automatically"
                ),
            )
            .await;
        }

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
            // Latch only when this overflow actually CONVERTED an admitted entry.
            // With zero Ok entries the batch's real cause is whatever the
            // per-entry loop already latched, and overwriting it would replace a
            // precise class with a coarser one.
            if actual_calls > 0 {
                self.record_http_denial(
                    reason_class::EXECUTION_RATE_LIMIT,
                    reason_class::WIT_FORBIDDENHOST,
                );
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
        // The execution's cancellation flag, cloned into every entry future:
        // the moved futures have no `self`, and a cancel arriving mid-batch
        // must stop the entries that have not been sent yet.
        let cancelled_flag = self.cancelled.clone();
        /// What one dispatched entry learned about its host, for the
        /// per-host permit settle after the join. `None` on the slot = the
        /// entry never reached `send()` (validation-failed, breaker-refused,
        /// dry-run).
        #[derive(Clone, Copy)]
        enum BatchSendOutcome {
            Status(u16),
            Transport,
            /// `reqwest` never built the request — a guest-authored header
            /// it refused. Nothing left the process (`settle_no_evidence`).
            NoEvidence,
            /// Observed cancellation before its send.
            Cancelled,
        }
        let stream =
            futures_util::stream::iter(validated.into_iter().enumerate().map(move |(idx, v)| {
                let max_r = max_resp;
                let self_http_client = self_http_client.clone();
                let cancelled_flag = cancelled_flag.clone();
                async move {
                    // Tag every future with its INPUT index: buffer_unordered
                    // yields in COMPLETION order, and the WIT contract
                    // promises `responses[i]` corresponds to `requests[i]`.
                    // Pre-fix, any batch whose requests finished out of
                    // order returned misattributed responses (silent
                    // cross-request data mix-up under the default
                    // concurrency of 10). The post-join sort restores the
                    // documented order.
                    let mut outcome: Option<BatchSendOutcome> = None;
                    let outcome_slot = &mut outcome;
                    let result = async move {
                        let (url_str, method, headers, body, timeout_ms) = match v {
                            Err(e) => return Err(e),
                            Ok(params) => params,
                        };

                // Per-ENTRY cancellation at dispatch time. With the default
                // concurrency of 10, a 100-entry batch has 90 entries queued
                // behind `buffer_unordered` when a cancel lands; each of them
                // checks the flag as it is polled for the first time.
                if cancelled_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    *outcome_slot = Some(BatchSendOutcome::Cancelled);
                    return Err(wit_http::Error::Networkerror);
                }

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

                // ── The circuit breaker and `fetch_all` ──────────────────────
                // Admission happened BEFORE the budget charge, per BATCH per
                // HOST (`host_permits` above) — this future holds no permit
                // and no `self`; it only REPORTS what it saw, via
                // `outcome_slot`, and the settle happens after the join, once
                // per distinct host. From 2026-08-11 to 2026-09 this path took
                // no permit at all; the per-batch-per-host shape is the one
                // the note that sat here argued for (per-ENTRY admission
                // would trip a 5-consecutive-failure breaker inside one guest
                // call and spend all three half-open trial tokens on what is
                // one sample against one host). `wit_webhook::send` now takes
                // a permit too; `wit_graphql::execute`, `host/http_stream.rs`,
                // the S3 operations, `llm_tools`, `llm` and `email` still do
                // not — see `circuit_breaker.rs`'s header for the list.
                let response = builder.send().await.map_err(|e| {
                    *outcome_slot = Some(if e.is_builder() {
                        BatchSendOutcome::NoEvidence
                    } else {
                        BatchSendOutcome::Transport
                    });
                    if e.is_timeout() {
                        wit_http::Error::Timeout
                    } else {
                        wit_http::Error::Networkerror
                    }
                })?;

                let status = response.status().as_u16();
                *outcome_slot = Some(BatchSendOutcome::Status(status));
                // Audit log: host + path LENGTH only (never the full URL or the
                // path — query params AND paths carry secrets: capability
                // tokens, presigned keys).
                if let Ok(parsed_url) = url::Url::parse(&url_str) {
                    tracing::info!(
                        method = %method_str_for_audit,
                        host = %parsed_url.host_str().unwrap_or("unknown"),
                        path_len = parsed_url.path().len(),
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
                    (idx, result, outcome)
                }
            }));

        #[allow(clippy::type_complexity)]
        let mut indexed: Vec<(
            usize,
            Result<wit_http::Response, wit_http::Error>,
            Option<BatchSendOutcome>,
        )> = stream.buffer_unordered(concurrency_limit).collect().await;
        // Restore the documented input order (see the tagging comment
        // above) — completion order is an implementation detail.
        indexed.sort_unstable_by_key(|&(i, _, _)| i);

        // ── Settle the per-host permits with the WORST outcome per host ──────
        // Transport failure > any status (a 5xx fails a half-open trial, a 2xx
        // passes it — `settle_response` decides) > builder-only failures (no
        // evidence about the host). A host whose entries were ALL cancelled
        // or dry-run has its permit dropped unsettled, which repays any trial
        // token and records neither outcome (see `RequestPermit`).
        let mut any_dispatch_cancelled = false;
        for (host, mut permit) in host_permits.drain() {
            let mut saw_transport = false;
            let mut worst_status: Option<u16> = None;
            let mut saw_no_evidence = false;
            for (idx, _, outcome) in &indexed {
                if request_hosts.get(*idx).and_then(|h| h.as_deref()) != Some(host.as_str()) {
                    continue;
                }
                match outcome {
                    Some(BatchSendOutcome::Transport) => saw_transport = true,
                    Some(BatchSendOutcome::Status(st)) => {
                        worst_status = Some(worst_status.map_or(*st, |w| w.max(*st)));
                    }
                    Some(BatchSendOutcome::NoEvidence) => saw_no_evidence = true,
                    Some(BatchSendOutcome::Cancelled) => any_dispatch_cancelled = true,
                    None => {}
                }
            }
            if saw_transport {
                permit.settle_transport_failure();
            } else if let Some(st) = worst_status {
                permit.settle_response(st);
            } else if saw_no_evidence {
                permit.settle_no_evidence();
            }
            // else: dropped unsettled → repaid.
        }
        // Per-failure diagnostics for DISPATCH failures. Validation
        // failures (request_hosts[i] == None) were already diagnosed at
        // validation time; capped globally by HOST_DIAG_CAP.
        // Same predicate as the single-fetch path: the posture the resolver
        // was actually built with, NOT `max_llm_tier == Tier1`. See
        // `TalosContext::local_egress_only`.
        let egress_gated = self.local_egress_only;
        // The batch's DISPATCH failures cannot latch from where they happen —
        // the send/response path runs inside a moved future with no `self`
        // (see the comment above `builder.send()`). That left every one of
        // them returning an UNLATCHED `networkerror`, which was invisible
        // while `networkerror` was only ever raised by `host::http`, and is
        // not any more: `wit_graphql`'s policy denials are now paired with the
        // same discriminant. An unlatched `networkerror` is a message a stale
        // graphql capability denial could be stamped onto — and the two shapes
        // that matter here (a transport failure and a mid-stream body error)
        // are GENUINELY TRANSIENT, so that would suppress a retry they are
        // entitled to. The 2026-07-23 outage class, one surface over.
        //
        // So the batch decides the latch ONCE, after the loop, rather than
        // per-entry: per-entry writes would race each other (entry 1's clear
        // erasing entry 0's egress class) purely on completion order.
        // `egress_attributed` records that the loop wrote a real class;
        // `unattributed_dispatch_failure` records that at least one entry
        // failed with no class of its own. VALIDATION failures are excluded by
        // construction — they carry `request_hosts[idx] == None`, never enter
        // the guard below, and keep the class they latched at validation time.
        let mut egress_attributed = false;
        let mut unattributed_dispatch_failure = false;
        for (idx, r, outcome) in &indexed {
            if let Err(e) = r {
                // A cancelled entry is diagnosed once, below, with the class
                // that keeps it from being redispatched.
                if matches!(outcome, Some(BatchSendOutcome::Cancelled)) {
                    continue;
                }
                // Breaker-refused entries were diagnosed at admission time.
                if request_hosts
                    .get(*idx)
                    .and_then(|h| h.as_deref())
                    .is_some_and(|h| breaker_refused.contains(h))
                {
                    continue;
                }
                if let Some(Some(host)) = request_hosts.get(*idx) {
                    unattributed_dispatch_failure = true;
                    // A Networkerror under a local-egress-only actor is almost
                    // always that gate (same reasoning as the single-fetch
                    // path); surface the actionable reason instead of the
                    // ambiguous connection/reset class.
                    //
                    // `emit_network_failure` (not the bare diagnostic) so the
                    // class also reaches the retry gates. `fetch_all` does not
                    // otherwise participate in the reason latch — its send
                    // path runs inside a moved future with no `self` — but the
                    // egress deny is the one class where getting it wrong is a
                    // CORRECTNESS bug rather than a diagnostic one: without
                    // the marker the batch's bare `networkerror` is now
                    // transient by default and a deny that cannot change
                    // between attempts would burn the retry budget.
                    if egress_gated && matches!(e, wit_http::Error::Networkerror) {
                        self.emit_network_failure(
                            reason_class::TIER1_EGRESS,
                            reason_class::WIT_NETWORKERROR,
                            &format!(
                                "fetch_all[{idx}]: '{host}' blocked by this workflow's actor \
                                 (local-egress-only). Set the actor's egress_scope to \
                                 'public' or bind a Tier-2 actor to reach external APIs."
                            ),
                        )
                        .await;
                        egress_attributed = true;
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
        // CLEAR rather than latch: the moved future is gone by now, so the
        // honest transport class is no longer recoverable, and inventing one
        // would be worse than none. Clearing is provably transience-neutral
        // for every shape this can produce — a bare `networkerror` is
        // TRANSIENT in both gates with or without a marker, and `timeout` is
        // transient in both — while leaving the latch alone would let an
        // unrelated stale class decide the retry.
        if unattributed_dispatch_failure && !egress_attributed {
            self.record_network_outcome(None);
        }
        // Cancellation last, so it WINS the latch: a batch cut short by a
        // cancel must classify `cancelled` (non-transient in both gates)
        // whatever its already-dispatched siblings did.
        if any_dispatch_cancelled {
            if let Some(ref m) = self.metrics {
                m.record_execution_cancelled();
            }
            self.emit_network_failure(
                reason_class::CANCELLED,
                reason_class::WIT_NETWORKERROR,
                "the execution was cancelled while the batch was in flight; \
                 entries not yet sent were not sent",
            )
            .await;
        }
        indexed.into_iter().map(|(_, r, _)| r).collect()
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
        let auth_value = match self
            .provider
            .into_auth_header(talos_secrets::SlotHandle(slot), "Authorization")
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(slot, error = %e, "fetch-with-bearer: slot lookup failed");
                // Slot number only — never the vault path or the value.
                self.emit_network_failure(
                    reason_class::SECRET_LOOKUP,
                    reason_class::WIT_NETWORKERROR,
                    &format!(
                        "secret slot {slot} could not be resolved for the Authorization \
                         header; the request was not sent"
                    ),
                )
                .await;
                return Err(wit_http::Error::Networkerror);
            }
        };
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
        let header_value = match self
            .provider
            .into_auth_header(talos_secrets::SlotHandle(slot), &header_name)
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(slot, header_name, error = %e, "fetch-with-header: slot lookup failed");
                // Slot number + the caller's own header name only.
                self.emit_network_failure(
                    reason_class::SECRET_LOOKUP,
                    reason_class::WIT_NETWORKERROR,
                    &format!(
                        "secret slot {slot} could not be resolved for the '{header_name}' \
                         header; the request was not sent"
                    ),
                )
                .await;
                return Err(wit_http::Error::Networkerror);
            }
        };
        // L-4: Zeroizing<String> → owned String at point of use; the
        // wrapper wipes when its scope ends.
        let owned_value = (*header_value).clone();
        drop(header_value);
        req.headers.insert(0, (header_name, owned_value));
        self.fetch(req).await
    }
}

/// Every exit that sits between the circuit breaker's admission and the
/// outcome settle in [`wit_http::Host::fetch`], driven through the real
/// `fetch` on a real [`TalosContext`], asserting that the half-open trial
/// token comes back.
///
/// The enumeration these cover is by CONTROL FLOW, not by grepping for
/// `return` — the inventory that shipped with #636 was built that way and
/// missed the `?` on `resolve_vault_header`, which is the one that fires
/// deterministically in production (an unresolvable `vault://oauth/...`
/// header, exactly the shape the calendar nodes use).
///
/// **Why each test targets its own TEST-NET-3 (RFC 5737) IP literal.** The
/// breaker is a process-global singleton keyed by host, so tests must not
/// share a host or they interfere. An IP literal is used rather than a
/// hostname because `fetch` resolves DNS for domain hosts BEFORE reaching the
/// breaker, and a name that does not resolve returns early — the request would
/// never reach the code under test. `url::Host::Ipv4` skips that block
/// entirely, and 203.0.113.0/24 is reserved-for-documentation, so it is not
/// classified private (it reaches the breaker) and can never be routed
/// anywhere (no test emits a packet).
///
/// LIMITATION, stated rather than implied: cancellation is NOT covered here.
/// Dropping `fetch`'s future mid-flight requires it to be parked on an await,
/// and the only awaits between the admission and the settle are the vault
/// resolve and `send()` itself — a race, not a fixture. Cancellation is
/// covered deterministically at the permit level by
/// `circuit_breaker::tests::a_cancelled_future_repays_its_trial_token`, which
/// parks on a `pending()` in exactly that window.
#[cfg(test)]
mod breaker_permit_leak_path_tests {
    use super::*;
    // The `fetch` under test is a trait method; without the trait in scope the
    // call does not resolve.
    use crate::bindings::talos::core::http::Host as _;
    use crate::circuit_breaker::get_global_circuit_breaker;
    use crate::context::TalosContext;
    use crate::wit_inspector::CapabilityWorld;
    use std::collections::HashMap;
    use talos_workflow_job_protocol::LlmTier;

    fn ctx_for(host: &str) -> TalosContext {
        TalosContext::new(
            CapabilityWorld::Http,
            vec![host.to_string()],
            // Empty secret grant: this is what makes the `vault://` resolve
            // below fail deterministically.
            vec![],
            128,
            HashMap::new(),
            None,
            None,
            false,
            None,
            std::sync::Arc::new(crate::expose_fallback::ExposeFallback::new()),
            LlmTier::default(),
            None,
        )
        .expect("test context")
    }

    fn get(host: &str) -> wit_http::Request {
        wit_http::Request {
            method: wit_http::Method::Get,
            url: format!("https://{host}/probe"),
            headers: vec![],
            body: vec![],
            timeout_ms: Some(1_000),
        }
    }

    /// Drive one leak path twice and assert BOTH halves of the claim.
    ///
    /// **Leg 1, the anti-vacuity leg.** With the circuit half-open and ZERO
    /// tokens, this request shape must be REFUSED by the breaker, which
    /// `fetch` surfaces as `Networkerror` from the circuit-open branch. Without
    /// this leg the whole module could pass for the wrong reason: a request
    /// rejected BEFORE the breaker — a DNS failure, a host-allowlist miss, a
    /// capability deny — also leaves the token count untouched, and "the token
    /// was never spent" is indistinguishable from "the token was spent and
    /// repaid" if you only look at the count. This leg proves the request
    /// reaches `begin_request` at all.
    ///
    /// **Leg 2, the repayment.** One token, a fresh context, the same request:
    /// the exit under test is taken and the token must come back, with neither
    /// trial tally moved.
    async fn assert_reaches_breaker_and_repays<C, B>(host: &str, what: &str, ctx: C, build: B)
    where
        C: Fn() -> TalosContext,
        B: Fn() -> wit_http::Request,
    {
        let cb = get_global_circuit_breaker();

        // Leg 1 — the breaker is genuinely on this request's path.
        cb.force_half_open(host, 0);
        let refused = ctx().fetch(build()).await;
        assert!(
            matches!(refused, Err(wit_http::Error::Networkerror)),
            "{what}: a zero-token half-open circuit did not refuse this request \
             ({refused:?}) — so this shape never reaches the breaker and the \
             repayment assertion below would pass vacuously"
        );

        // Leg 2 — the exit under test repays its token.
        cb.force_half_open(host, 1);
        assert_eq!(cb.trial_tokens_remaining(host), Some(1));
        let _ = ctx().fetch(build()).await;

        assert_eq!(
            cb.trial_tokens_remaining(host),
            Some(1),
            "{what}: the half-open trial token was spent and never repaid. Three of \
             these strand the host at half-open-with-zero-tokens for the life of the \
             worker process — HalfOpen has no time bound and nothing refills it."
        );
        assert_eq!(
            cb.get_state(host).as_deref(),
            Some("half_open"),
            "{what}: the circuit must be exactly where it started"
        );
        assert_eq!(
            cb.trial_tally(host),
            Some((0, 0)),
            "{what}: an abandoned trial must record neither a success nor a failure"
        );
    }

    /// Leak path 1 — the outbound header-count cap. `return Err(...)`.
    #[tokio::test]
    async fn header_cap_rejection_repays_the_trial_token() {
        let host = "203.0.113.11";
        assert_reaches_breaker_and_repays(
            host,
            "header cap",
            || ctx_for(host),
            || {
                let mut req = get(host);
                req.headers = (0..=MAX_OUTBOUND_HEADERS)
                    .map(|i| (format!("x-probe-{i}"), "v".to_string()))
                    .collect();
                req
            },
        )
        .await;
    }

    /// Leak path 2 — the outbound body-size cap. `return Err(...)`.
    #[tokio::test]
    async fn body_cap_rejection_repays_the_trial_token() {
        let host = "203.0.113.12";
        assert_reaches_breaker_and_repays(
            host,
            "body cap",
            || ctx_for(host),
            || {
                let mut req = get(host);
                req.body = vec![0u8; MAX_OUTBOUND_HTTP_BODY_BYTES + 1];
                req
            },
        )
        .await;
    }

    /// Leak path 3 — `resolve_vault_header(...)?`. **A `?`, not a `return`**,
    /// which is why the previous grep-based inventory missed it, and the one
    /// that fires deterministically in production: an OAuth secret that is
    /// missing, expired or not granted to the module denies here every time,
    /// on the exact header shape the calendar nodes use.
    #[tokio::test]
    async fn unresolvable_vault_header_repays_the_trial_token() {
        let host = "203.0.113.13";
        assert_reaches_breaker_and_repays(
            host,
            "unresolvable vault:// header",
            || ctx_for(host),
            || {
                let mut req = get(host);
                req.headers = vec![(
                    "authorization".to_string(),
                    "Bearer vault://oauth/gcal/nobody/access_token".to_string(),
                )];
                req
            },
        )
        .await;
    }

    /// Seed the store the way a completed POST `https://{host}/probe` with body
    /// `{}` under `user` would (tenancy-scoped key + request hash — E1).
    fn seed_dedup(user: uuid::Uuid, host: &str, key: &str, status: u16, body: &[u8]) {
        let scoped = scoped_dedup_key(Some(user), None, host, key).expect("user present");
        let hash = dedup_request_hash("POST", &format!("https://{host}/probe"), b"{}");
        get_global_idempotency_store().complete(
            &scoped,
            &hash,
            DedupResponse {
                status,
                headers: vec![],
                body: body.to_vec(),
            },
        );
    }

    /// Former leak path 4 — the idempotency dedup short-circuit, a
    /// `return Ok(cached)` that USED to sit between the permit and the send.
    /// Since 2026-09 the dedup check is hoisted ahead of the DNS lookup and the
    /// breaker, so a cached hit never asks for admission at all: with a
    /// zero-token half-open circuit (which refuses every request that DOES
    /// reach the breaker) the cached response is still served and no token
    /// moves. That is a stronger guarantee than repayment, and this test pins
    /// it in that direction.
    #[tokio::test]
    async fn idempotency_dedup_short_circuit_never_reaches_the_breaker() {
        let host = "203.0.113.14";
        let key = "breaker-permit-dedup-probe";
        let user = uuid::Uuid::new_v4();
        seed_dedup(user, host, key, 200, b"cached");
        let cb = get_global_circuit_breaker();
        cb.force_half_open(host, 0);

        let mut ctx = ctx_for(host);
        ctx.user_id = Some(user);
        ctx.idempotency_key = Some(key.to_string());
        let mut req = get(host);
        // The dedup store is only consulted for MUTATING verbs.
        req.method = wit_http::Method::Post;
        req.body = b"{}".to_vec();

        let resp = ctx
            .fetch(req)
            .await
            .expect("cached hit is served ahead of the breaker");
        assert_eq!(resp.status, 200);
        assert_eq!(
            cb.trial_tokens_remaining(host),
            Some(0),
            "no token was touched"
        );
        assert_eq!(cb.trial_tally(host), Some((0, 0)));
    }

    /// The dedup path must still return the cached response — the permit must
    /// not have changed what `fetch` does, only what it accounts for.
    #[tokio::test]
    async fn the_dedup_short_circuit_still_returns_the_cached_response() {
        let host = "203.0.113.15";
        let key = "breaker-permit-dedup-passthrough";
        let user = uuid::Uuid::new_v4();
        seed_dedup(user, host, key, 201, b"cached-body");

        let mut ctx = ctx_for(host);
        ctx.user_id = Some(user);
        ctx.idempotency_key = Some(key.to_string());
        let mut req = get(host);
        req.method = wit_http::Method::Post;
        req.body = b"{}".to_vec();

        let resp = ctx.fetch(req).await.expect("dedup hit returns Ok");
        assert_eq!(resp.status, 201);
        assert_eq!(resp.body, b"cached-body".to_vec());
    }

    /// A CLOSED circuit — every request on a healthy worker — must be wholly
    /// unaffected by the permit. No token exists to repay, the guard's `Drop`
    /// touches no map, and the same leak paths leave no trace at all.
    #[tokio::test]
    async fn a_closed_circuit_is_untouched_by_any_of_the_leak_paths() {
        let host = "203.0.113.16";
        let cb = get_global_circuit_breaker();
        let mut ctx = ctx_for(host);
        let mut req = get(host);
        req.headers = (0..=MAX_OUTBOUND_HEADERS)
            .map(|i| (format!("x-probe-{i}"), "v".to_string()))
            .collect();

        assert!(matches!(
            ctx.fetch(req).await,
            Err(wit_http::Error::Forbiddenhost)
        ));

        assert_eq!(
            cb.get_state(host).as_deref(),
            Some("closed"),
            "a guest-side rejection must not move a healthy circuit in any direction"
        );
        assert_eq!(cb.consecutive_failures(host), Some(0));
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

#[cfg(test)]
mod idempotency_dedup_tests {
    //! E1 (2026-09): the worker-side dedup store is process-global, and until
    //! this change it was keyed on the LITERAL engine-stamped key with no
    //! request identity — two tenants (or two unrelated workflows of one
    //! tenant) using the same literal were served each other's cached 2xx.
    //! Every test here drives the REAL `fetch` up to the dedup check, which
    //! now sits ahead of the DNS lookup, so no network is involved.
    use super::*;
    use crate::bindings::talos::core::http::Host as _;
    use crate::context::TalosContext;
    use crate::wit_inspector::CapabilityWorld;
    use std::collections::HashMap;
    use talos_workflow_job_protocol::LlmTier;

    const HOST: &str = "example.invalid";

    fn ctx(user: Option<uuid::Uuid>, key: &str) -> TalosContext {
        let mut c = TalosContext::new(
            CapabilityWorld::Http,
            vec![HOST.to_string()],
            vec![],
            128,
            HashMap::new(),
            None,
            None,
            false,
            None,
            std::sync::Arc::new(crate::expose_fallback::ExposeFallback::new()),
            LlmTier::Tier2,
            None,
        )
        .expect("test context");
        c.user_id = user;
        c.idempotency_key = Some(key.to_string());
        c
    }

    fn post(body: &[u8]) -> wit_http::Request {
        wit_http::Request {
            method: wit_http::Method::Post,
            url: format!("https://{HOST}/charges"),
            headers: vec![],
            body: body.to_vec(),
            timeout_ms: Some(1_000),
        }
    }

    /// Seed the global store exactly as a completed send under `user` would.
    fn seed(user: uuid::Uuid, key: &str, body: &[u8]) {
        let scoped = scoped_dedup_key(Some(user), None, HOST, key).expect("user present");
        let hash = dedup_request_hash("POST", &format!("https://{HOST}/charges"), body);
        get_global_idempotency_store().complete(
            &scoped,
            &hash,
            DedupResponse {
                status: 201,
                headers: vec![],
                body: b"cached".to_vec(),
            },
        );
    }

    #[test]
    fn scoped_key_is_namespaced_by_tenancy_and_absent_without_a_user() {
        let u1 = uuid::Uuid::new_v4();
        let u2 = uuid::Uuid::new_v4();
        let a = uuid::Uuid::new_v4();
        let k1 = scoped_dedup_key(Some(u1), None, "Api.Example.com", "lit").unwrap();
        let k2 = scoped_dedup_key(Some(u2), None, "api.example.com", "lit").unwrap();
        let k1a = scoped_dedup_key(Some(u1), Some(a), "api.example.com", "lit").unwrap();
        let k1h = scoped_dedup_key(Some(u1), None, "other.example.com", "lit").unwrap();
        assert_ne!(k1, k2, "same literal, different user → different key");
        assert_ne!(k1, k1a, "actor is part of the namespace");
        assert_ne!(k1, k1h, "host is part of the namespace");
        assert_eq!(
            k1,
            format!("{u1}:-:api.example.com:lit"),
            "host is lowercased"
        );
        assert!(
            scoped_dedup_key(None, None, "h", "lit").is_none(),
            "no tenancy principal → the store is not engaged"
        );
    }

    #[tokio::test]
    async fn same_literal_different_user_is_a_miss() {
        let key = format!("lit-{}", uuid::Uuid::new_v4());
        let owner = uuid::Uuid::new_v4();
        seed(owner, &key, b"{\"amount\":1}");

        // Control: the owner IS served the cached response (before any DNS).
        let r = ctx(Some(owner), &key).fetch(post(b"{\"amount\":1}")).await;
        match r {
            Ok(resp) => {
                assert_eq!(resp.status, 201);
                assert_eq!(resp.body, b"cached");
            }
            other => panic!("owner must be served the cached response, got {other:?}"),
        }

        // The defect: a DIFFERENT user with the same literal + same request
        // must NOT see the owner's response. It falls through to DNS on a
        // `.invalid` host, which fails — anything but the cached 201 proves
        // the miss.
        let stranger = uuid::Uuid::new_v4();
        let r = ctx(Some(stranger), &key)
            .fetch(post(b"{\"amount\":1}"))
            .await;
        assert!(
            !matches!(&r, Ok(resp) if resp.status == 201),
            "a different tenant was served the owner's cached response: {r:?}"
        );

        // No user id at all: the store is not engaged either.
        let r = ctx(None, &key).fetch(post(b"{\"amount\":1}")).await;
        assert!(
            !matches!(&r, Ok(resp) if resp.status == 201),
            "a principal-less job was served a cached response: {r:?}"
        );
    }

    #[tokio::test]
    async fn same_key_different_request_is_refused_not_served() {
        let key = format!("lit-{}", uuid::Uuid::new_v4());
        let owner = uuid::Uuid::new_v4();
        seed(owner, &key, b"{\"amount\":1}");

        let mut c = ctx(Some(owner), &key);
        let r = c.fetch(post(b"{\"amount\":2}")).await;
        assert!(
            matches!(r, Err(wit_http::Error::Forbiddenhost)),
            "same key, different body must be REFUSED, got {r:?}"
        );
        // Refusal clears the latch (no minted class; `forbiddenhost` is
        // non-transient by discriminant).
        assert!(c.network_reason_handle().lock().unwrap().is_none());
        // And the store still holds the ORIGINAL record — a mismatch must not
        // overwrite it.
        let r = ctx(Some(owner), &key).fetch(post(b"{\"amount\":1}")).await;
        assert!(matches!(r, Ok(resp) if resp.status == 201));
    }

    /// A GET never engages the store (no header, no dedup), even under a
    /// stamped key — a read is safe to repeat.
    #[tokio::test]
    async fn get_never_touches_the_store() {
        let key = format!("lit-{}", uuid::Uuid::new_v4());
        let owner = uuid::Uuid::new_v4();
        // Seed under the GET's own identity so a wrongly-engaged store WOULD hit.
        let scoped = scoped_dedup_key(Some(owner), None, HOST, &key).unwrap();
        let hash = dedup_request_hash("GET", &format!("https://{HOST}/charges"), b"");
        get_global_idempotency_store().complete(
            &scoped,
            &hash,
            DedupResponse {
                status: 299,
                headers: vec![],
                body: vec![],
            },
        );
        let req = wit_http::Request {
            method: wit_http::Method::Get,
            url: format!("https://{HOST}/charges"),
            headers: vec![],
            body: vec![],
            timeout_ms: Some(1_000),
        };
        let r = ctx(Some(owner), &key).fetch(req).await;
        assert!(
            !matches!(&r, Ok(resp) if resp.status == 299),
            "GET was served from the store: {r:?}"
        );
    }
}

#[cfg(test)]
mod fetch_all_budget_and_breaker_tests {
    //! E3 (2026-09): `fetch_all` validated an unbounded batch before consulting
    //! the budget, and took no circuit-breaker permit at all.
    use super::*;
    use crate::bindings::talos::core::http::Host as _;
    use crate::circuit_breaker::get_global_circuit_breaker;
    use crate::context::TalosContext;
    use crate::wit_inspector::CapabilityWorld;
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;
    use talos_workflow_job_protocol::LlmTier;

    fn ctx(allowed: &[&str], dry_run: bool) -> TalosContext {
        let mut c = TalosContext::new(
            CapabilityWorld::Http,
            allowed.iter().map(|s| s.to_string()).collect(),
            vec![],
            128,
            HashMap::new(),
            None,
            None,
            false,
            None,
            std::sync::Arc::new(crate::expose_fallback::ExposeFallback::new()),
            LlmTier::Tier2,
            None,
        )
        .expect("test context");
        c.dry_run = dry_run;
        c
    }

    fn latched(c: &TalosContext) -> Option<&'static str> {
        c.network_reason_handle().lock().unwrap().map(|r| r.class)
    }

    fn bogus() -> wit_http::Request {
        wit_http::Request {
            method: wit_http::Method::Get,
            url: "not a url".to_string(),
            headers: vec![],
            body: vec![],
            timeout_ms: None,
        }
    }

    #[tokio::test]
    async fn a_batch_larger_than_the_remaining_budget_is_refused_before_validation() {
        let mut c = ctx(&["*"], false);
        c.http_call_count
            .store(MAX_HTTP_CALLS_PER_EXECUTION - 1, Ordering::Relaxed);
        let out = c.fetch_all(vec![bogus(), bogus()]).await;
        assert_eq!(out.len(), 2);
        // Refused as a batch: every slot is `Forbiddenhost` — NOT the
        // `Invalidurl` per-entry validation would have produced, which is
        // what proves validation never ran.
        assert!(
            out.iter()
                .all(|r| matches!(r, Err(wit_http::Error::Forbiddenhost))),
            "{out:?}"
        );
        assert_eq!(
            c.http_call_count.load(Ordering::Relaxed),
            MAX_HTTP_CALLS_PER_EXECUTION - 1,
            "a refused batch must not be charged"
        );
        assert_eq!(latched(&c), Some(reason_class::EXECUTION_RATE_LIMIT));

        // Control: with room for both, the same batch IS validated (and each
        // entry fails on its own merits).
        let mut c = ctx(&["*"], false);
        c.http_call_count
            .store(MAX_HTTP_CALLS_PER_EXECUTION - 2, Ordering::Relaxed);
        let out = c.fetch_all(vec![bogus(), bogus()]).await;
        assert!(
            out.iter()
                .all(|r| matches!(r, Err(wit_http::Error::Invalidurl))),
            "{out:?}"
        );
    }

    fn post_to(host: &str, path: &str) -> wit_http::Request {
        wit_http::Request {
            method: wit_http::Method::Post,
            url: format!("https://{host}/{path}"),
            headers: vec![],
            body: b"{}".to_vec(),
            timeout_ms: Some(1_000),
        }
    }

    /// One permit per DISTINCT host per batch: an open circuit refuses every
    /// entry to that host without charging budget; an admitted batch of two
    /// entries spends ONE trial token, and (dry-run: nothing sent) repays it.
    #[tokio::test]
    async fn breaker_admission_is_per_batch_per_host() {
        // A public IP literal skips DNS, and dry-run mocks the POST before any
        // socket is opened — so the only I/O-shaped thing on this path is the
        // breaker itself. Unique host per test: the breaker is process-global.
        let host = "8.8.4.4";
        let cb = get_global_circuit_breaker();

        // Refused: half-open with zero tokens.
        cb.force_half_open(host, 0);
        let mut c = ctx(&[host], true);
        let out = c
            .fetch_all(vec![post_to(host, "a"), post_to(host, "b")])
            .await;
        assert!(
            out.iter()
                .all(|r| matches!(r, Err(wit_http::Error::Networkerror))),
            "an open circuit must refuse every entry to that host: {out:?}"
        );
        assert_eq!(
            c.http_call_count.load(Ordering::Relaxed),
            0,
            "refused entries cost no budget"
        );
        assert_eq!(latched(&c), Some(reason_class::CIRCUIT_OPEN));

        // Admitted: ONE token for the whole batch, repaid because dry-run
        // produced no evidence about the host.
        cb.force_half_open(host, 1);
        let mut c = ctx(&[host], true);
        let out = c
            .fetch_all(vec![post_to(host, "a"), post_to(host, "b")])
            .await;
        assert!(
            out.iter()
                .all(|r| matches!(r, Ok(resp) if resp.status == 200)),
            "{out:?}"
        );
        assert_eq!(
            c.http_call_count.load(Ordering::Relaxed),
            2,
            "admitted entries are charged"
        );
        assert_eq!(
            cb.trial_tokens_remaining(host),
            Some(1),
            "a two-entry batch must spend exactly one trial token and, unsettled, repay it"
        );
        assert_eq!(cb.trial_tally(host), Some((0, 0)));
    }
}
