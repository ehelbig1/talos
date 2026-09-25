//! `http-stream` (SSE consumption) host interface.

use super::*;

use crate::reason_class;

/// Latch `class` against the `forbidden-host` discriminant and return it.
///
/// The `http-stream` WIT enum spells its cases with HYPHENS — `invalid-url`,
/// `forbidden-host`, `connection-failed`, `rate-limited` — and wit-bindgen
/// renders the case name verbatim into the guest's `Debug` and `Display`
/// output. So `forbiddenhost`, the token every existing classifier arm keys
/// on, does NOT match: a `forbidden-host` denial instead matched the substring
/// `forbidden` and was filed as `auth_failure` / `http_403`, pointing the
/// operator at a credential that was never the problem. Non-transient either
/// way, so this whole file is a remediation fix, not a retry fix.
///
/// Unlike `graphql` and `webhook`, the pairing here is NOT vacuous: every
/// `ForbiddenHost` and every `InvalidUrl` site is a policy denial, and no
/// transport failure returns either.
///
/// `ConnectionFailed` is the mixed one. Until 2026-09 it was raised only by a
/// cancellation and two mutex-poison guards, because the connection was
/// established INSIDE the spawned SSE task and a transport failure there had
/// no path back to the guest — `connect` answered `Ok(stream_id)` and the
/// stream then yielded nothing, so a module could not tell a dead connection
/// from a quiet endpoint. Measured on the unmodified tree: `connect` returned
/// `Ok`, the latch was `None`, and `next_event` answered `None` in 795 µs.
/// The connection-establishment phase now runs in `connect` itself, so that
/// discriminant additionally carries the four transport classes
/// [`reason_class::classify_reqwest_send_error`] can mint. None of them makes
/// a `connection-failed` message transient (checked exhaustively by
/// `no_stream_class_can_grant_a_new_retry`); `timeout` would, which is why the
/// pre-header stall collapses to [`reason_class::CONNECT_FAILED`] instead.
fn stream_deny_forbidden(ctx: &TalosContext, class: &'static str) -> wit_http_stream::Error {
    ctx.record_http_denial(class, reason_class::WIT_FORBIDDEN_HOST_HYPHENATED);
    wit_http_stream::Error::ForbiddenHost
}

/// Latch `class` against the hyphenated `invalid-url` discriminant.
/// Sibling of [`stream_deny_forbidden`]; see its doc for the spelling trap.
fn stream_deny_invalid_url(ctx: &TalosContext, class: &'static str) -> wit_http_stream::Error {
    ctx.record_http_denial(class, reason_class::WIT_INVALID_URL_HYPHENATED);
    wit_http_stream::Error::InvalidUrl
}

/// Latch `class` against the hyphenated `rate-limited` discriminant.
fn stream_deny_rate_limited(ctx: &TalosContext, class: &'static str) -> wit_http_stream::Error {
    ctx.record_http_denial(class, reason_class::WIT_RATE_LIMITED);
    wit_http_stream::Error::RateLimited
}

// ============================================================================
// HTTP Stream (SSE consumption)
// ============================================================================

impl TalosContext {
    /// Latch the honest transport class for a failed SSE connection-ESTABLISHMENT
    /// send, publish the operator diagnostic, and hand back the discriminant.
    ///
    /// Sibling of [`TalosContext::record_graphql_transport_outcome`], and a
    /// named method for the same testing reason: the SSE transport path cannot
    /// be reached from a hermetic test through the front door — every route to
    /// it passes the SSRF gate, which is the point of the gate — so the
    /// properties are proven by calling THIS function with a real
    /// `reqwest::Error`, i.e. the same call with the same argument the
    /// production site makes.
    ///
    /// `classify_reqwest_send_error` reads the SOURCE CHAIN only, never
    /// reqwest's `Display` (which appends the full URL and its query string).
    /// It can return exactly four tokens — `tls`, `connect-refused`,
    /// `connect-failed`, `send-failed` — and NONE of them makes a
    /// `connection-failed` message read transient, so this cannot grant a
    /// retry that did not exist. It is `timeout` that would, and this function
    /// can never mint it.
    pub(crate) async fn record_stream_transport_outcome(
        &mut self,
        host: &str,
        e: &reqwest::Error,
    ) -> wit_http_stream::Error {
        let class = reason_class::classify_reqwest_send_error(e);
        // The sanitized raw detail is WORKER-LOG ONLY and never crosses the
        // host→guest boundary: URL erased, DLP-redacted, IP/path-sanitized.
        // Gated on the SAME per-execution `HOST_DIAG_CAP` the diagnostic
        // channel spends — and the `emit_network_failure` below is what SPENDS
        // it — so this is not a second, unbounded stream.
        if self.host_diag_budget_remaining() {
            tracing::warn!(
                module_id = ?self.module_id,
                host,
                reason = class,
                detail = %reason_class::sanitized_transport_detail(e),
                "wit_http_stream::connect transport failure (sanitized transport detail)"
            );
        }
        // Same attribution split as `host::http`'s send path, and it keys on
        // `local_egress_only` — the posture this context's own client was
        // BUILT with — never on `max_llm_tier == Tier1`, which disagrees with
        // it in both directions since the `egress_scope` split.
        if reason_class::is_local_egress_attributable(class, self.local_egress_only) {
            self.emit_network_failure(
                reason_class::TIER1_EGRESS,
                reason_class::WIT_CONNECTION_FAILED,
                &format!(
                    "the SSE stream to '{host}' was blocked by this workflow's actor \
                     (local-egress-only — data must not leave the host). To reach an \
                     external endpoint, set the actor's egress_scope to 'public' \
                     (set_actor_egress_scope) or bind a Tier-2 actor."
                ),
            )
            .await;
            return wit_http_stream::Error::ConnectionFailed;
        }
        // Fixed prose per class — never the reqwest string. `host` is safe to
        // name: the module author declared it in `allowed_hosts`. The path,
        // the query string and the resolved IP are not, and none appears here.
        let prose = match class {
            reason_class::TLS => "the TLS handshake failed (certificate or protocol)",
            reason_class::CONNECT_REFUSED => "the peer refused the connection",
            reason_class::CONNECT_FAILED => {
                "the connection could not be established (unreachable or no route)"
            }
            _ => "the request failed after connecting (reset or protocol error)",
        };
        self.emit_network_failure(
            class,
            reason_class::WIT_CONNECTION_FAILED,
            &format!("the SSE stream to '{host}' could not be opened: {prose}"),
        )
        .await;
        wit_http_stream::Error::ConnectionFailed
    }

    /// The endpoint accepted the TCP/TLS connection and then never sent
    /// response headers within the establishment budget.
    ///
    /// COLLAPSED to [`reason_class::CONNECT_FAILED`] rather than given the
    /// honest [`reason_class::TIMEOUT`], and that is a deliberate, load-bearing
    /// choice rather than sloppiness. `connection-failed` reads NON-transient
    /// bare, and `runtime::is_transient_error_text` matches the bare substring
    /// `timeout` — so a `[reason_class=timeout]` marker on this discriminant
    /// would move the message from non-transient to TRANSIENT and newly grant
    /// a retry to a surface that has never had one. That is the one direction
    /// this workspace has already paid for, so the class stays inside the
    /// non-transient set and the precise variant ("timed out before response
    /// headers") is carried by the `[host:…]` diagnostic instead. Same
    /// collapse-and-explain shape as [`reason_class::PRIVATE_IP`] and
    /// [`reason_class::GRAPHQL_INTROSPECTION`].
    ///
    /// Deliberately does NOT consult `is_local_egress_attributable`: under
    /// local-egress-only the resolver hands hyper an EMPTY address list, which
    /// fails IMMEDIATELY as a connect error — it never stalls — so attributing
    /// a stall to the egress gate would point the operator at the wrong knob.
    pub(crate) async fn record_stream_connect_stall(
        &mut self,
        host: &str,
        budget_secs: u64,
    ) -> wit_http_stream::Error {
        self.emit_network_failure(
            reason_class::CONNECT_FAILED,
            reason_class::WIT_CONNECTION_FAILED,
            &format!(
                "the SSE endpoint at '{host}' accepted the connection but sent no \
                 response headers within {budget_secs}s, so the stream was abandoned"
            ),
        )
        .await;
        wit_http_stream::Error::ConnectionFailed
    }

    /// The endpoint answered the connect with a non-2xx status. No event can
    /// ever arrive on such a stream, so `connect` refuses instead of handing
    /// back a stream id that will only ever end.
    ///
    /// CLEARS the latch rather than stamping one. There is no honest token for
    /// "the upstream said 404" in the closed [`reason_class::ALL`] set, and
    /// minting one is not free: `talos_reason_class::Family` is deliberately
    /// not `#[non_exhaustive]`, so a genuinely new remediation family forces
    /// every controller-side classifier to be edited in the same change, and
    /// mapping it onto an existing family would be a lie (an HTTP error status
    /// is not a transport failure and not a policy denial). Clearing satisfies
    /// #717's totality rule — every failing return DECIDES the latch — leaves
    /// the guest with the correct non-transient bare `connection-failed`, and
    /// still tells the operator the status through the diagnostic channel.
    ///
    /// The status is an integer parsed by the HTTP stack, not guest- or
    /// upstream-authored text, so interpolating it obeys the sanitization
    /// contract. It reaches `workflow_execution_logs`, never the node-failure
    /// message the retry gates scan — which matters, because that gate matches
    /// the bare substrings "429", "502", "503" and "504".
    pub(crate) async fn record_stream_upstream_status(
        &mut self,
        host: &str,
        status: u16,
    ) -> wit_http_stream::Error {
        self.record_network_outcome(None);
        self.emit_host_diagnostic(
            "sse-upstream-status",
            &format!(
                "the SSE endpoint at '{host}' answered the connect with HTTP {status} \
                 instead of a 2xx, so no events can arrive on this stream"
            ),
        )
        .await;
        wit_http_stream::Error::ConnectionFailed
    }

    /// Turn an abnormal [`SseStreamEnd`] into ONE operator diagnostic.
    ///
    /// Called from `next_event` at the exact moment the guest observes the
    /// stream ending, which is the only moment a `&mut self` exists — the
    /// spawned reader has no context to emit from. The guest still sees plain
    /// `None`, because `next-event -> option<sse-event>` has no error arm and
    /// widening it would invalidate 75 catalog templates' checked-in
    /// `bindings.rs`.
    ///
    /// NO reason class is latched. Nothing is returned to the guest here for a
    /// class to explain, and a latch with no paired discriminant is precisely
    /// the stale-marker hazard [`reason_class::Reason`] exists to prevent — it
    /// would sit in the slot waiting to be stamped onto an unrelated later
    /// failure on any surface sharing the token.
    pub(crate) async fn report_stream_end(&mut self, end: crate::context::SseStreamEnd) {
        let (reason, message) = end.describe();
        self.emit_host_diagnostic(reason, message).await;
    }
}

impl wit_http_stream::Host for TalosContext {
    async fn connect(
        &mut self,
        url: String,
        headers: Vec<(String, String)>,
    ) -> Result<String, wit_http_stream::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if matches!(
            self.capability_world,
            CapabilityWorld::Minimal | CapabilityWorld::Unknown
        ) {
            // MCP-697 (2026-05-13): audit-ledger parity. SSE-stream connect
            // is the 5th Tier-1 LLM-egress surface (per the host_impl Tier-1
            // commentary); the host-allowlist denial branch farther down
            // audits, the capability-world branch was silent. Record host
            // (or empty placeholder if URL parse fails downstream) so the
            // ledger captures which target the Minimal-world probe tried.
            let target_host = url::Url::parse(&url)
                .ok()
                .and_then(|u| u.host_str().map(|h| h.to_string()))
                .unwrap_or_default();
            self.record_capability_denied(
                "wit_http_stream::connect",
                "capability-world",
                &target_host,
            )
            .await;
            return Err(stream_deny_forbidden(self, reason_class::CAPABILITY_WORLD));
        }
        if self.is_cancelled() {
            self.record_http_denial(reason_class::CANCELLED, reason_class::WIT_CONNECTION_FAILED);
            return Err(wit_http_stream::Error::ConnectionFailed);
        }

        // MCP-1148: cap URL bytes BEFORE the main `url::Url::parse`
        // at line ~10283. Sibling-parity with wit_http::fetch /
        // wit_graphql / wit_webhook. The audit-only parse in the
        // capability-world denial branch above uses `.ok()` and only
        // fires for Minimal-world probes — a rare denial path — so the
        // hot-path parse cost lives below this gate.
        if url.len() > MAX_OUTBOUND_URL_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                url_len = url.len(),
                limit = MAX_OUTBOUND_URL_BYTES,
                "wit_http_stream::connect rejected: URL length exceeds cap"
            );
            return Err(stream_deny_invalid_url(self, reason_class::URL_TOO_LONG));
        }

        // Enforce concurrent stream cap.
        {
            let streams = self.streams.sse.lock().map_err(|_| {
                // A poisoned mutex is a host-internal fault, not an egress
                // outcome, so there is no honest class for it — CLEAR, so a
                // swallowed earlier denial cannot be stamped onto it. This is
                // the totality rule: every failing return DECIDES the latch.
                self.record_network_outcome(None);
                wit_http_stream::Error::ConnectionFailed
            })?;
            if streams.len() >= MAX_SSE_STREAMS_PER_EXECUTION {
                tracing::warn!(
                    module_id = ?self.module_id,
                    active = streams.len(),
                    "SSE stream limit reached ({} max)",
                    MAX_SSE_STREAMS_PER_EXECUTION
                );
                return Err(stream_deny_rate_limited(self, reason_class::SSE_STREAM_CAP));
            }
        }

        // Parse and validate URL (same SSRF protections as http::fetch).
        let parsed: url::Url = url
            .parse()
            .map_err(|_| stream_deny_invalid_url(self, reason_class::URL_PARSE))?;

        let host = parsed.host_str().unwrap_or("").to_string();

        // HTTPS-only by default. SSE streams stay open for the full
        // event window so an on-path attacker who can read plaintext
        // wins ANY secret rotated through `vault://` headers for the
        // life of the connection — strictly worse than a one-shot
        // fetch. Operator opt-in via `WASM_ALLOW_INSECURE_HTTP=1`.
        match classify_url_scheme(parsed.scheme(), insecure_http_opt_in()) {
            UrlSchemeVerdict::Https => {}
            UrlSchemeVerdict::InsecureAllowedByOptIn { scheme } => {
                tracing::warn!(
                    scheme = %scheme,
                    host = %host,
                    "http-stream: insecure-scheme stream allowed by WASM_ALLOW_INSECURE_HTTP=1"
                );
            }
            UrlSchemeVerdict::InsecureRefused { scheme } => {
                self.record_capability_denied(
                    "http-stream",
                    "insecure-scheme",
                    &format!("{scheme} {host}"),
                )
                .await;
                tracing::warn!(
                    scheme = %scheme,
                    host = %host,
                    "WASM module attempted non-https SSE stream — denied."
                );
                return Err(stream_deny_invalid_url(self, reason_class::INSECURE_SCHEME));
            }
        }

        if self.allowed_hosts.is_empty() {
            self.record_capability_denied("http-stream", "no-allowlist-configured", &host)
                .await;
            return Err(stream_deny_forbidden(self, reason_class::NO_ALLOWLIST));
        }
        // Method allowlist (2026-09-24). This surface had NO method gate at
        // all, which mattered the moment an EMPTY `allowed_methods` started
        // denying on the other four: without this, "an undeclared module
        // cannot make HTTP calls" would have been false — it could still open
        // an SSE read stream. An SSE connect is a GET (the WIT `connect(url,
        // headers)` carries no method and the protocol is GET by
        // construction), so that is the verb it must declare. Measured before
        // adding it: exactly ONE module on the reference fleet mentions
        // `http_stream` and it declares all five verbs, so the live blast
        // radius here is zero — which is also why the empty-list arm directly
        // above (`allowed_hosts`) is the right precedent to sit beside.
        if !talos_workflow_job_protocol::method_permitted(&self.allowed_methods, "GET") {
            self.record_capability_denied_detailed(
                "http-stream",
                "method-allowlist",
                &format!("GET {host}"),
                Some(talos_workflow_job_protocol::METHOD_ALLOWLIST_REMEDY),
            )
            .await;
            tracing::warn!(
                host = %host,
                allowed_methods = ?self.allowed_methods,
                "WASM module attempted an SSE stream but GET is not in allowed_methods"
            );
            return Err(stream_deny_forbidden(self, reason_class::METHOD_ALLOWLIST));
        }
        // SSRF: block private IPs via the shared classifier (covers
        // CGNAT and IPv4-mapped IPv6 the duplicated logic was missing).
        if let Some((ip, policy)) = denied_ip_literal(&parsed) {
            self.record_capability_denied("http-stream", policy, &ip.to_string())
                .await;
            tracing::warn!(
                ip = %ip,
                policy,
                "WASM module attempted SSE stream to a private IP literal — blocking"
            );
            return Err(stream_deny_forbidden(self, reason_class::PRIVATE_IP));
        }
        let host_match = match host_allowlist_match_kind(&self.allowed_hosts, &host) {
            Some(kind) => kind,
            None => {
                self.record_capability_denied("http-stream", "allowed-hosts", &host)
                    .await;
                return Err(stream_deny_forbidden(self, reason_class::ALLOWED_HOSTS));
            }
        };
        // Strict-egress gate: an SSE connect is a READ channel, but its URL
        // is guest-influenceable outbound data — same exfil surface as a
        // GET (see http.rs fetch). Read-only actors under
        // `TALOS_WRITE_CEILING_STRICT_EGRESS=1` may stream only from
        // operator-NAMED hosts; wildcard admissions are refused.
        if self
            .read_egress_refuses("http-stream", &host, host_match)
            .await
        {
            return Err(stream_deny_forbidden(
                self,
                reason_class::WRITE_CEILING_STRICT_EGRESS,
            ));
        }

        // DNS rebinding — same shared check used by fetch / webhook / graphql.
        if matches!(parsed.host(), Some(url::Host::Domain(_))) {
            // The ONE mixed site — an SSRF answer (deterministic denial) and a
            // resolver failure (transient, not a denial) share one `Err`. The
            // resolver failure CLEARS rather than latching `dns`, for the same
            // reason as `webhook`: `forbidden-host` is non-transient today and
            // `dns` is in the transient bucket, so latching it would newly
            // grant a retry that does not exist.
            if let Err(e) = self.validate_no_dns_rebinding(&host, "http-stream").await {
                return Err(match reason_class::dns_rebinding_class(e) {
                    Some(class) => stream_deny_forbidden(self, class),
                    None => {
                        self.record_network_outcome(None);
                        wit_http_stream::Error::ForbiddenHost
                    }
                });
            }
        }

        // Tier-1 LLM egress ceiling — SSE stream to an external LLM
        // would exfiltrate via streaming-response reads. Deny here too.
        // Egress-posture gate: tier-1 LLM hosts + public IP literals, and
        // public IP literals for ANY local-egress-only actor (a resolver never
        // sees a literal) — one predicate, `egress_posture_deny_reason`.
        {
            let host_lower = host.to_ascii_lowercase();
            if let Some(policy) =
                egress_posture_deny_reason(&host_lower, self.max_llm_tier, self.local_egress_only)
            {
                self.record_capability_denied("http-stream", policy, &host)
                    .await;
                tracing::warn!(
                    host = %host,
                    actor_id = ?self.actor_id,
                    policy,
                    "actor egress posture refused HTTP stream egress (tier-1: external LLM host or public IP literal; local-only egress: public IP literal)"
                );
                return Err(stream_deny_forbidden(
                    self,
                    reason_class::tier1_egress_class(policy),
                ));
            }
        }

        // L-finding-7 (2026-05-23): per-host cumulative SSE-connect cap.
        // Sibling-parity with the HTTP per-host rate limit (M-6 in
        // `wit_http::fetch`) — charged AFTER all upstream-target
        // validation has admitted (SSRF, allowlist, scheme, tier-1
        // ceiling) so a bogus URL doesn't waste budget. Host key is
        // normalised to `host:port` lowercased to match
        // `http_calls_per_host`'s slot semantics. Failed admission
        // burns NO slot on the host's bookkeeping (the bump only
        // happens on the headroom path) so a denied caller can't
        // accidentally pump the counter against a third party.
        let sse_host_key = match parsed.port_or_known_default() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        if !self
            .check_sse_per_host_rate_limit(&sse_host_key, MAX_SSE_CONNECTS_PER_HOST_PER_EXECUTION)
        {
            self.record_capability_denied("http-stream", "per-host-rate-limit", &host)
                .await;
            tracing::warn!(
                module_id = ?self.module_id,
                host = %host,
                limit = MAX_SSE_CONNECTS_PER_HOST_PER_EXECUTION,
                "SSE per-host connect cap exceeded — refusing to amplify load against a single upstream"
            );
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("sse_per_host");
            }
            return Err(stream_deny_rate_limited(
                self,
                reason_class::PER_HOST_RATE_LIMIT,
            ));
        }

        // MCP-1105: cap caller-supplied header count. See
        // MAX_OUTBOUND_HEADERS doc-comment. SSE streams are long-lived
        // (kept open for the full execution timeout) so even one
        // bloated connection ties up host memory + the vault-resolve
        // cost compounds across reconnects.
        if headers.len() > MAX_OUTBOUND_HEADERS {
            tracing::warn!(
                module_id = ?self.module_id,
                header_count = headers.len(),
                limit = MAX_OUTBOUND_HEADERS,
                "wit_http_stream::connect rejected: header count exceeds cap"
            );
            return Err(stream_deny_forbidden(
                self,
                reason_class::REQUEST_HEADER_CAP,
            ));
        }
        // Resolve vault:// headers.
        let resolved_headers: Vec<(String, String)> = {
            let mut hdrs = Vec::with_capacity(headers.len());
            for (k, v) in &headers {
                let resolved = self
                    .resolve_vault_header(
                        crate::context::SecretUseSurface::HttpStreamHeader,
                        &host,
                        k.as_str(),
                        v.as_str(),
                    )
                    .await
                    .map_err(|_| stream_deny_forbidden(self, reason_class::SECRET_LOOKUP))?;
                hdrs.push((k.clone(), resolved.into_owned()));
            }
            hdrs
        };

        // ── Connection establishment runs HERE, not in the spawned task ────
        //
        // This is the 2026-09 fix for the silent-connect-failure gap. Before
        // it, everything below the `tokio::spawn` boundary — the send, the
        // establishment timeout and the status check — failed with no path
        // back to the guest: `connect` had already answered `Ok(stream_id)`,
        // so the module saw a healthy stream that happened to carry no events
        // and could not distinguish that from a quiet endpoint. It could not
        // retry, report, or log what it never learned about.
        //
        // Awaiting here is what makes the failure KNOWABLE before a stream id
        // is minted, which is the only shape the WIT permits: `connect` is
        // `result<string, error>` and can carry `connection-failed`, while
        // `next-event` is `option<sse-event>` and has no error arm at all.
        //
        // Two consequences, both accepted deliberately:
        //   * `connect` now blocks for up to the establishment budget. It is
        //     not new latency — pre-fix the guest blocked for exactly as long
        //     inside its first `next_event`, then got `None` — but it does
        //     SERIALISE the establishment of several streams that previously
        //     raced. With MAX_SSE_STREAMS_PER_EXECUTION = 5 the pathological
        //     all-stalling case is 5 × the budget. Truthfulness wins.
        //   * `resolved_headers` (which may carry `vault://`-substituted
        //     secrets) is consumed HERE and no longer moved into a long-lived
        //     spawned task. Strictly less secret lifetime than before.
        let mut req_builder = self
            .http_client
            .get(&url)
            .header("Accept", "text/event-stream")
            .header("Cache-Control", "no-cache");
        for (k, v) in resolved_headers {
            req_builder = req_builder.header(k, v);
        }

        // MCP-721 (2026-05-13): cap the initial connection-establishment
        // phase at 30 s. Pre-fix `req_builder.send().await` had no timeout —
        // if the SSE server stalled (never sent response headers) the task
        // hung indefinitely. SSE legitimately needs long-lived BODIES, so
        // ONLY establishment is bounded; the bytes_stream loop below stays
        // unbounded (that is the point of streaming) and is policed instead by
        // the cancellation flag.
        const SSE_CONNECT_TIMEOUT_SECS: u64 = 30;
        let response = match tokio::time::timeout(
            std::time::Duration::from_secs(SSE_CONNECT_TIMEOUT_SECS),
            req_builder.send(),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Err(self.record_stream_transport_outcome(&host, &e).await),
            Err(_) => {
                return Err(self
                    .record_stream_connect_stall(&host, SSE_CONNECT_TIMEOUT_SECS)
                    .await)
            }
        };

        let status = response.status();
        if !status.is_success() {
            return Err(self
                .record_stream_upstream_status(&host, status.as_u16())
                .await);
        }

        // ── Only now is a stream id minted and registered ─────────────────
        //
        // The registration used to sit ABOVE the header cap and the vault
        // resolve, so either of those returning `Err` leaked a dead receiver
        // into `streams.sse` that nothing ever removed. Measured on the
        // unmodified tree: three connects with an unresolvable `vault://`
        // header grew the map 1 → 2 → 3 while every call returned
        // `forbidden-host`. MAX_SSE_STREAMS_PER_EXECUTION is 5, so a handful
        // of FAILED connects permanently exhausted an execution's stream
        // budget. Registering last makes the leak unreachable by
        // construction rather than by remembering to clean up on each path.
        let (tx, rx) = tokio::sync::mpsc::channel::<crate::context::SseChannelItem>(1_000);
        let stream_id = uuid::Uuid::new_v4().to_string();
        {
            let mut streams = self.streams.sse.lock().map_err(|_| {
                // Host-internal fault; CLEAR (see the sibling guard above).
                self.record_network_outcome(None);
                wit_http_stream::Error::ConnectionFailed
            })?;
            streams.insert(stream_id.clone(), rx);
        }

        let url_owned = url.clone();
        // Wasm-security review 2026-05-23 (M): clone the execution's
        // cancellation flag into the spawned task so it can exit
        // promptly when the parent execution is cancelled. Pre-fix the
        // task only noticed cancellation via mpsc receiver-drop, which
        // doesn't fire while the task is blocked in
        // `StreamExt::next(&mut stream)` waiting on slow upstream
        // bytes — leaving the connection / spawned task alive past
        // execution-end and consuming a worker connection slot.
        let cancelled = self.cancelled.clone();
        let idle_timeout =
            std::time::Duration::from_secs(talos_config::positive_env_or_default::<u64>(
                "TALOS_SSE_IDLE_TIMEOUT_SECS",
                SSE_STREAM_IDLE_TIMEOUT_SECS,
            ));

        // MCP-670: `=0`-safe env helper. `TALOS_SSE_MAX_EVENT_BYTES=0`
        // would abort every SSE stream on the first received byte, so the
        // whole streaming surface silently breaks under helm misconfig.
        const DEFAULT_SSE_MAX_BYTES: usize = 1024 * 1024;
        let max_event_bytes: usize = talos_config::positive_env_or_default::<usize>(
            "TALOS_SSE_MAX_EVENT_BYTES",
            DEFAULT_SSE_MAX_BYTES,
        );
        // The raw `reqwest::Error` never crosses into the reader's logic: each
        // body error is reduced to the SANITIZED detail here, which is all the
        // reader ever logged.
        let body = futures_util::StreamExt::map(response.bytes_stream(), |r| {
            r.map_err(|e| reason_class::sanitized_transport_detail(&e).to_string())
        });
        let buffered_budget = std::sync::Arc::new(tokio::sync::Semaphore::new(
            MAX_SSE_BUFFERED_BYTES_PER_STREAM,
        ));
        let reader = tokio::spawn(run_sse_reader(
            body,
            tx,
            SseReaderConfig {
                url: url_owned,
                cancelled,
                idle_timeout,
                max_event_bytes,
                buffered_budget,
            },
        ));
        // Keep the handle so `close()` and registry drop (execution end) can
        // ABORT the reader — see `StreamRegistry::sse_tasks`.
        self.streams.register_sse_task(&stream_id, reader);

        Ok(stream_id)
    }

    async fn next_event(&mut self, stream_id: String) -> Option<wit_http_stream::SseEvent> {
        // Take the receiver out so we don't hold the mutex during await.
        let mut rx = {
            let mut streams = self.streams.sse.lock().ok()?;
            streams.remove(&stream_id)?
        };

        let item = rx.recv().await;

        // Put back only if the stream can still produce events. A terminal
        // marker and a closed channel are both ENDINGS, so neither is
        // reinserted and a second call answers `None` from the map lookup.
        if matches!(item, Some(crate::context::SseChannelItem::Event(_))) {
            if let Ok(mut streams) = self.streams.sse.lock() {
                streams.insert(stream_id, rx);
            }
        } else {
            // Ended: the reader has returned (or is about to); drop its
            // handle so the registry does not hold finished tasks.
            self.streams.abort_sse_task(&stream_id);
        }

        match item {
            Some(crate::context::SseChannelItem::Event(e)) => Some(wit_http_stream::SseEvent {
                event_type: e.event_type,
                data: e.data,
                id: e.id,
            }),
            // The stream died rather than finishing. The guest still gets a
            // plain `None` — `next-event -> option<sse-event>` has no error
            // arm and widening it would invalidate the checked-in
            // `bindings.rs` of every catalog template — but the OPERATOR now
            // gets one `[host:…]` line saying which of the four endings it
            // was. Fires at most once per stream (the marker is the last item
            // and the receiver is not reinserted) and spends the same
            // `HOST_DIAG_CAP` budget as every other diagnostic.
            Some(crate::context::SseChannelItem::End(end)) => {
                self.report_stream_end(end).await;
                None
            }
            // Sender dropped with no marker: a clean upstream close, or a
            // `close()` that removed the receiver. Neither is a fault.
            None => None,
        }
    }

    async fn close(&mut self, stream_id: String) {
        // Removing the receiver causes the spawned task's tx.send() to fail,
        // which makes it exit cleanly — but only once it has something to
        // send. A reader blocked on a quiet upstream never reaches that
        // `send`, so the task is also ABORTED outright.
        if let Ok(mut streams) = self.streams.sse.lock() {
            streams.remove(&stream_id);
        }
        self.streams.abort_sse_task(&stream_id);
    }
}

/// Bytes of parsed-but-undelivered events one SSE stream may hold (2026-09-25).
///
/// The reader parses ahead of the guest into an mpsc channel of capacity 1 000,
/// and a single event may be up to `TALOS_SSE_MAX_EVENT_BYTES` (1 MiB default):
/// ~1 GiB per stream, ×`MAX_SSE_STREAMS_PER_EXECUTION`, parked in worker memory
/// for a guest that simply stops calling `next-event`. Each event now holds a
/// share of this budget (one permit per byte) until the guest RECEIVES it, so
/// once 4 MiB are queued the reader stops reading the socket and TCP pushes
/// back on the server. The channel's item count still bounds tiny events.
pub(crate) const MAX_SSE_BUFFERED_BYTES_PER_STREAM: usize = 4 * 1024 * 1024;

/// Everything the SSE reader needs besides the body and the channel.
pub(crate) struct SseReaderConfig {
    pub(crate) url: String,
    pub(crate) cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(crate) idle_timeout: std::time::Duration,
    pub(crate) max_event_bytes: usize,
    pub(crate) buffered_budget: std::sync::Arc<tokio::sync::Semaphore>,
}

/// The spawned body of one SSE stream: read the body, parse events, deliver
/// them in order, and announce an abnormal ending. A free function over a
/// byte stream (not a `reqwest::Response`) so it is testable with a synthetic
/// body; errors arrive already sanitized.
pub(crate) async fn run_sse_reader<S>(
    mut stream: S,
    tx: tokio::sync::mpsc::Sender<crate::context::SseChannelItem>,
    config: SseReaderConfig,
) where
    S: futures_util::Stream<Item = Result<bytes::Bytes, String>> + Unpin,
{
    use crate::context::{SseChannelItem, SseStreamEnd};
    let SseReaderConfig {
        url: url_owned,
        cancelled,
        idle_timeout,
        max_event_bytes,
        buffered_budget,
    } = config;

    // Why an abnormal ending is ANNOUNCED rather than just logged: a
    // mid-stream reset, a byte-cap trip and a clean upstream close are
    // all `next_event -> None` to the guest, and `option<sse-event>`
    // cannot be widened without invalidating every catalog template's
    // checked-in bindings. So the reader posts one terminal marker on
    // the channel it already owns and `next_event` converts it into a
    // single operator diagnostic. A CLEAN close posts nothing — it
    // simply drops `tx` — so the signal means "this stream died", not
    // "this stream finished".
    //
    // `try_send` on a full channel would drop the marker, and
    // `send().await` is correct here: ordering after the last event is
    // the whole point, and an `Err` just means the guest already
    // stopped listening.
    async fn announce(tx: &tokio::sync::mpsc::Sender<SseChannelItem>, end: SseStreamEnd) {
        let _ = tx.send(SseChannelItem::End(end)).await;
    }

    let mut parser = SseParser::new(max_event_bytes);
    let mut last_byte_at = std::time::Instant::now();

    loop {
        // Wasm-security review 2026-05-23 (M): bound the
        // bytes-stream wait so a slow-trickle upstream can't
        // keep this task alive past execution-end. The
        // `tokio::select!` races the next chunk against:
        //   - a short periodic wake (200 ms) that checks the
        //     execution's cancellation flag,
        //   - the cancellation flag itself flipping mid-wait
        //     (cooperative — we ALSO short-circuit on the
        //     wake-tick if the flag is set, so no race window).
        // The periodic wake is cheap (200 ms = 5 polls/sec)
        // and gives the task at most 200 ms of slack between
        // cancellation and exit.
        let chunk_result = tokio::select! {
            chunk = futures_util::StreamExt::next(&mut stream) => chunk,
            _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {
                if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                    tracing::debug!(
                        url = %url_owned,
                        "SSE stream task observed execution cancellation — exiting"
                    );
                    announce(&tx, SseStreamEnd::Cancelled).await;
                    return;
                }
                // Idle window (see `SSE_STREAM_IDLE_TIMEOUT_SECS`):
                // checked on the same tick, so a silent-but-open
                // upstream cannot hold this task past the window.
                if last_byte_at.elapsed() >= idle_timeout {
                    tracing::warn!(
                        url = %url_owned,
                        idle_secs = idle_timeout.as_secs(),
                        "SSE stream idle timeout — no bytes received within window; closing"
                    );
                    announce(&tx, SseStreamEnd::IdleTimeout).await;
                    return;
                }
                continue;
            }
        };
        last_byte_at = std::time::Instant::now();
        let chunk_result = match chunk_result {
            // Clean upstream close: the ONLY ending that announces
            // nothing, because it is the only one where an empty tail
            // is the honest answer.
            Some(c) => c,
            None => break,
        };
        let chunk = match chunk_result {
            Ok(c) => c,
            Err(detail) => {
                // Pre-2026-09 this was a bare `Err(_) => break` — the
                // ONE failure mode on this surface that logged nothing
                // ANYWHERE, host or guest. Bounded: it terminates the
                // loop, so at most one line per stream and at most
                // MAX_SSE_STREAMS_PER_EXECUTION per execution.
                tracing::warn!(
                    url = %url_owned,
                    detail = %detail,
                    "SSE stream failed mid-body (sanitized transport detail)"
                );
                announce(&tx, SseStreamEnd::TransportError).await;
                return;
            }
        };

        let (events, abort) = parser.feed(&chunk);
        for mut event in events {
            // Hold a share of the stream's buffered-bytes budget until the
            // guest receives this event (see MAX_SSE_BUFFERED_BYTES_PER_STREAM).
            // Clamped to the whole budget so an event larger than it (possible
            // when TALOS_SSE_MAX_EVENT_BYTES is raised) waits for an empty
            // queue instead of deadlocking.
            let cost = event
                .buffered_len()
                .clamp(1, MAX_SSE_BUFFERED_BYTES_PER_STREAM);
            let Ok(permit) = buffered_budget
                .clone()
                .acquire_many_owned(u32::try_from(cost).unwrap_or(u32::MAX))
                .await
            else {
                return; // budget closed: nothing is listening
            };
            event.buffered = Some(permit);
            if tx.send(SseChannelItem::Event(event)).await.is_err() {
                return; // Receiver dropped (close called)
            }
        }
        if let Some(abort) = abort {
            tracing::warn!(
                url = %url_owned,
                max_bytes = max_event_bytes,
                "SSE stream exceeded max event size (unterminated line or oversized \
                 data before a blank-line boundary); aborting stream"
            );
            announce(&tx, abort).await;
            return;
        }
    }
}

/// The SSE line protocol, fed one body chunk at a time.
///
/// **Linear since 2026-09-25.** The reader used to consume each complete line
/// with `buffer = buffer[nl_pos + 1..].to_string()` — a fresh copy of the WHOLE
/// remaining buffer per line — so a chunk of many short lines cost
/// O(lines × buffer): half a million `\n` in a 1 MiB buffer is ~2.5·10¹¹ bytes
/// of memcpy. Lines are now read through a cursor and the consumed prefix is
/// drained ONCE per chunk. The semantics are unchanged byte for byte (pinned
/// against the retained per-line reference by
/// `the_cursor_parser_agrees_with_the_copying_reference`), including both caps:
/// an un-newlined buffer over `max_event_bytes` aborts before any of its lines
/// are read, and accumulated `data:` over `max_event_bytes` aborts at the line
/// that crosses it, after delivering the events completed before it.
pub(crate) struct SseParser {
    buffer: String,
    event_type: Option<String>,
    data_lines: Vec<String>,
    data_bytes: usize,
    event_id: Option<String>,
    max_event_bytes: usize,
}

impl SseParser {
    pub(crate) fn new(max_event_bytes: usize) -> Self {
        Self {
            buffer: String::new(),
            event_type: None,
            data_lines: Vec::new(),
            data_bytes: 0,
            event_id: None,
            max_event_bytes,
        }
    }

    /// Append `chunk` and return the events it completed, plus the abort the
    /// chunk triggered, if any (the events are still delivered first).
    pub(crate) fn feed(
        &mut self,
        chunk: &[u8],
    ) -> (
        Vec<crate::context::SseEventInternal>,
        Option<crate::context::SseStreamEnd>,
    ) {
        use crate::context::SseStreamEnd;
        // SECURITY: cap both the incoming-byte buffer and the per-event
        // accumulated data. A misbehaving server that never emits a blank
        // line would otherwise grow `data_lines` monotonically until the
        // worker OOMs, and one huge line with no `\n` would grow `buffer`.
        self.buffer.push_str(&String::from_utf8_lossy(chunk));
        let mut events = Vec::new();
        if self.buffer.len() > self.max_event_bytes {
            return (events, Some(SseStreamEnd::EventBytesCap));
        }
        let mut consumed = 0usize;
        let mut abort = None;
        while let Some(rel) = self.buffer[consumed..].find('\n') {
            let nl_pos = consumed + rel;
            let line = self.buffer[consumed..nl_pos].trim_end_matches('\r');
            consumed = nl_pos + 1;
            if line.is_empty() {
                // Blank line = event boundary
                if !self.data_lines.is_empty() {
                    events.push(crate::context::SseEventInternal {
                        event_type: self.event_type.take(),
                        data: self.data_lines.join("\n"),
                        id: self.event_id.take(),
                        buffered: None,
                    });
                    self.data_lines.clear();
                    self.data_bytes = 0;
                }
            } else if let Some(value) = line.strip_prefix("data:") {
                let v = value.trim_start().to_string();
                self.data_bytes = self.data_bytes.saturating_add(v.len()).saturating_add(1);
                if self.data_bytes > self.max_event_bytes {
                    abort = Some(SseStreamEnd::EventBytesCap);
                    break;
                }
                self.data_lines.push(v);
            } else if let Some(value) = line.strip_prefix("event:") {
                self.event_type = Some(value.trim_start().to_string());
            } else if let Some(value) = line.strip_prefix("id:") {
                self.event_id = Some(value.trim_start().to_string());
            }
            // Skip comments (lines starting with :) and retry: fields
        }
        self.buffer.drain(..consumed);
        (events, abort)
    }
}

#[cfg(test)]
mod sse_reader_bound_tests {
    use super::*;
    use crate::context::{SseChannelItem, SseEventInternal, SseStreamEnd};
    use std::time::{Duration, Instant};

    /// The pre-2026-09-25 per-line parse, verbatim in its string handling,
    /// kept only as the reference the cursor parser is checked against.
    struct CopyingReference {
        buffer: String,
        event_type: Option<String>,
        data_lines: Vec<String>,
        data_bytes: usize,
        event_id: Option<String>,
        max: usize,
    }

    impl CopyingReference {
        fn feed(&mut self, chunk: &[u8]) -> (Vec<(Option<String>, String, Option<String>)>, bool) {
            let mut out = Vec::new();
            self.buffer.push_str(&String::from_utf8_lossy(chunk));
            if self.buffer.len() > self.max {
                return (out, true);
            }
            while let Some(nl_pos) = self.buffer.find('\n') {
                let line = self.buffer[..nl_pos].trim_end_matches('\r').to_string();
                self.buffer = self.buffer[nl_pos + 1..].to_string();
                if line.is_empty() {
                    if !self.data_lines.is_empty() {
                        out.push((
                            self.event_type.take(),
                            self.data_lines.join("\n"),
                            self.event_id.take(),
                        ));
                        self.data_lines.clear();
                        self.data_bytes = 0;
                    }
                } else if let Some(value) = line.strip_prefix("data:") {
                    let v = value.trim_start().to_string();
                    self.data_bytes = self.data_bytes.saturating_add(v.len()).saturating_add(1);
                    if self.data_bytes > self.max {
                        return (out, true);
                    }
                    self.data_lines.push(v);
                } else if let Some(value) = line.strip_prefix("event:") {
                    self.event_type = Some(value.trim_start().to_string());
                } else if let Some(value) = line.strip_prefix("id:") {
                    self.event_id = Some(value.trim_start().to_string());
                }
            }
            (out, false)
        }
    }

    fn triple(e: &SseEventInternal) -> (Option<String>, String, Option<String>) {
        (e.event_type.clone(), e.data.clone(), e.id.clone())
    }

    #[test]
    fn the_cursor_parser_agrees_with_the_copying_reference() {
        const PIECES: &[&str] = &[
            "data:", "data: x", "event: e", "id: 7", ": c", "\n", "\r\n", "\n\n", "ab", "retry: 1",
            "data:yy",
        ];
        let mut state: u64 = 0xD1B5_4A32_D192_ED03;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let mut events_seen = 0usize;
        for _ in 0..2_000 {
            let max = 16 + (next() % 64) as usize;
            let mut new = SseParser::new(max);
            let mut old = CopyingReference {
                buffer: String::new(),
                event_type: None,
                data_lines: Vec::new(),
                data_bytes: 0,
                event_id: None,
                max,
            };
            for _ in 0..(next() % 12) {
                let chunk: String = (0..(next() % 6))
                    .map(|_| PIECES[(next() % PIECES.len() as u64) as usize])
                    .collect();
                let (a_events, a_abort) = new.feed(chunk.as_bytes());
                let (b_events, b_abort) = old.feed(chunk.as_bytes());
                let a: Vec<_> = a_events.iter().map(triple).collect();
                assert_eq!(a, b_events, "events differ for chunk {chunk:?}");
                assert_eq!(
                    a_abort.is_some(),
                    b_abort,
                    "abort differs for chunk {chunk:?}"
                );
                events_seen += a.len();
                if b_abort {
                    break;
                }
            }
        }
        assert!(
            events_seen >= 200,
            "the generator must produce events ({events_seen})"
        );
    }

    /// A million short lines in one 4 MiB buffer (TALOS_SSE_MAX_EVENT_BYTES is
    /// operator-raisable; 4 MiB is a plausible setting). The copying parser
    /// re-copied the remaining buffer per line: ~2·10¹² bytes of memcpy here,
    /// minutes of CPU. The cursor parser is one pass.
    ///
    /// Measured at the 1 MiB DEFAULT the quadratic parser is not slow enough
    /// to catch on a fast machine: ~1.25·10¹¹ bytes of cache-resident memcpy
    /// took ~1.5 s here, so a 1 MiB fixture passed with the per-line copy
    /// restored. That is still a ~10⁵× byte amplification a server can repeat
    /// per chunk; it is just not a reliable test signal. Run on its own thread
    /// with a watchdog so a regression FAILS instead of hanging the suite.
    #[test]
    fn a_chunk_of_many_short_lines_parses_in_linear_time() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let chunk = ": c\n".repeat(1_048_576); // 4 MiB, all comment lines
            let mut p = SseParser::new(5 * 1024 * 1024);
            let start = Instant::now();
            let (events, abort) = p.feed(chunk.as_bytes());
            let _ = tx.send((events.len(), abort.is_some(), start.elapsed()));
        });
        let (events, aborted, elapsed) = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("a 4 MiB chunk of short lines must parse in one pass, not quadratically");
        assert_eq!((events, aborted), (0, false));
        assert!(elapsed < Duration::from_secs(10), "({elapsed:?})");
    }

    /// The bounded-MEMORY assertion: a server streaming 1 MiB events to a
    /// guest that never calls `next-event` fills the stream's byte budget and
    /// then the reader STOPS — it does not park 1 000 × 1 MiB in the channel.
    #[tokio::test]
    async fn a_stalled_guest_caps_the_bytes_the_reader_buffers() {
        let one_event = format!("data: {}\n\n", "z".repeat(1024 * 1024 - 64));
        let body = futures_util::stream::iter(
            (0..50).map(move |_| Ok::<_, String>(bytes::Bytes::from(one_event.clone()))),
        );
        let (tx, mut rx) = tokio::sync::mpsc::channel(1_000);
        let budget = std::sync::Arc::new(tokio::sync::Semaphore::new(
            MAX_SSE_BUFFERED_BYTES_PER_STREAM,
        ));
        let reader = tokio::spawn(run_sse_reader(
            body,
            tx,
            SseReaderConfig {
                url: "https://example.test/".to_string(),
                cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                idle_timeout: Duration::from_secs(60),
                max_event_bytes: 2 * 1024 * 1024,
                buffered_budget: budget.clone(),
            },
        ));
        // Give the reader every chance to run ahead.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let queued = rx.len();
        let queued_bytes = MAX_SSE_BUFFERED_BYTES_PER_STREAM - budget.available_permits();
        assert!(
            queued_bytes <= MAX_SSE_BUFFERED_BYTES_PER_STREAM,
            "queued {queued_bytes} bytes"
        );
        assert!(
            queued <= 4,
            "a stalled guest must hold at most the budget's worth of 1 MiB events, got {queued}"
        );
        assert!(
            !reader.is_finished(),
            "the reader must be waiting, not done"
        );
        // Draining releases the budget and the reader moves on.
        let mut received = 0;
        while let Some(item) = rx.recv().await {
            if let SseChannelItem::Event(_) = item {
                received += 1;
            }
            if received == 50 {
                break;
            }
        }
        assert_eq!(received, 50, "every event is still delivered, in time");
        reader.await.unwrap();
        assert_eq!(
            budget.available_permits(),
            MAX_SSE_BUFFERED_BYTES_PER_STREAM
        );
    }

    /// An event larger than the whole budget still gets through (it waits for
    /// an empty queue instead of deadlocking), when the operator has raised
    /// TALOS_SSE_MAX_EVENT_BYTES above the budget.
    #[tokio::test]
    async fn an_event_larger_than_the_budget_does_not_deadlock() {
        let big = format!(
            "data: {}\n\n",
            "q".repeat(MAX_SSE_BUFFERED_BYTES_PER_STREAM + 10)
        );
        let body = futures_util::stream::iter(vec![Ok::<_, String>(bytes::Bytes::from(big))]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let reader = tokio::spawn(run_sse_reader(
            body,
            tx,
            SseReaderConfig {
                url: "https://example.test/".to_string(),
                cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                idle_timeout: Duration::from_secs(60),
                max_event_bytes: 16 * 1024 * 1024,
                buffered_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(
                    MAX_SSE_BUFFERED_BYTES_PER_STREAM,
                )),
            },
        ));
        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("must not deadlock");
        assert!(matches!(got, Some(SseChannelItem::Event(_))));
        reader.await.unwrap();
        let _ = SseStreamEnd::EventBytesCap;
    }
}
