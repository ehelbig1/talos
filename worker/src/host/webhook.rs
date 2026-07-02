//! `webhook` sender host interface.

use super::*;

// ============================================================================
// Webhook sender
// ============================================================================

impl wit_webhook::Host for TalosContext {
    async fn send(
        &mut self,
        req: wit_webhook::WebhookRequest,
    ) -> Result<wit_webhook::WebhookResponse, wit_webhook::Error> {
        // MCP-785 (2026-05-14): pure-validation surfaces (URL parse,
        // host allowlist, SSRF IP-literal classification, allowed_hosts
        // pattern match, DNS-rebinding, Tier-1 LLM egress) MUST run
        // BEFORE `check_rate_limit` charges `webhook_send_count`.
        // Pre-fix the rate-limit charge ran first, so a guest could
        // loop `send(url="http://127.0.0.1/x", ...)` (SSRF deny) or
        // `send(url="https://blocked.example.com/x", ...)` (allowed-
        // hosts deny) up to MAX_WEBHOOK_SENDS_PER_EXECUTION times and
        // exhaust the per-execution webhook quota with zero outbound
        // POSTs ever leaving the worker. Subsequent legitimate
        // webhook sends were then blocked for the rest of the
        // execution despite the rate-limit being conceptually unused.
        // Same shape as MCP-770 (wit_files::write), MCP-783
        // (wit_http::fetch_all batch CAS), MCP-784 (wit_messaging
        // payload-size after rate-limit), and MCP-612 (the original
        // counter-only-advances-when-admitted rule).
        // MCP-537 (the original rate-limit add) is preserved — only
        // the ordering moves; cancellation check also relocates to
        // stay paired with the rate-limit charge.

        let url = req.url.clone();
        // MCP-1148: cap URL bytes BEFORE invoking `url::Url::parse`
        // below. Sibling-parity with wit_http::fetch / wit_graphql.
        if url.len() > MAX_OUTBOUND_URL_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                url_len = url.len(),
                limit = MAX_OUTBOUND_URL_BYTES,
                "wit_webhook::send rejected: URL length exceeds cap"
            );
            return Err(wit_webhook::Error::Sendfailed);
        }
        // MCP-1105: cap caller-supplied header count. See
        // MAX_OUTBOUND_HEADERS doc-comment for the per-vault-resolve
        // amplification rationale; wit_webhook::send's retry budget
        // (1 + max_retries) further compounds it.
        if req.headers.len() > MAX_OUTBOUND_HEADERS {
            tracing::warn!(
                module_id = ?self.module_id,
                header_count = req.headers.len(),
                limit = MAX_OUTBOUND_HEADERS,
                "wit_webhook::send rejected: header count exceeds cap"
            );
            return Err(wit_webhook::Error::Sendfailed);
        }
        let headers = req.headers.clone();
        // MCP-1014 (2026-05-15): cap caller-supplied webhook body. Pre-fix
        // `req.body` was unbounded — wasmtime-memory-budget the only
        // ceiling, which is the FLOOR (not the ceiling) of what the host
        // must defend against. A guest with a 100 MB memory budget could
        // ship a 100 MB body per send(); the host then cloned it twice
        // (into the local `body` binding and again into reqwest's
        // `.body(body.clone())` on each retry) and held it across the
        // network round-trip. With MAX_WEBHOOK_SENDS_PER_EXECUTION × the
        // 1 + max_retries retry budget, the worst-case host-memory
        // commitment compounds.
        //
        // The sibling response side already capped at
        // `MAX_WEBHOOK_RESP_BYTES = 1 MB` (line 5026); 10 MB on the
        // outbound matches the higher CSV/XML/template caps and is
        // generous for normal webhook traffic (typical payloads are
        // sub-100 KB). Same defense-in-depth class as MCP-1013
        // (wit_data_transform XML/JSON caps) and MCP-784
        // (wit_messaging payload-size).
        // MCP-1076: canonical module-level MAX_OUTBOUND_HTTP_BODY_BYTES.
        if req.body.len() > MAX_OUTBOUND_HTTP_BODY_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                body_len = req.body.len(),
                limit = MAX_OUTBOUND_HTTP_BODY_BYTES,
                "wit_webhook::send rejected: body exceeds cap"
            );
            return Err(wit_webhook::Error::Sendfailed);
        }
        let body = req.body.clone();
        // MCP-583: cap caller-supplied retry config. Pre-fix
        // `max_retries` and `retry_delay_ms` were `option<u32>` with
        // no upper bound — a module could pass `u32::MAX` for either
        // (or both) and a single send() with a non-timeout transport
        // error (e.g. connection-refused) would loop until the WASM
        // execution timeout, holding a worker slot. Sibling
        // wit_graphql caps its backoff at 30s; this is the lone
        // straggler. The design-doc "1+max_retries (default 4)
        // actual POSTs" promise (in `webhook_cap_holds_at_one_hundred`)
        // only holds with a bound here.
        let max_retries = req
            .max_retries
            .unwrap_or(3)
            .min(MAX_WEBHOOK_RETRIES_PER_SEND);
        let retry_delay_ms = req
            .retry_delay_ms
            .unwrap_or(1_000)
            .min(MAX_WEBHOOK_RETRY_DELAY_MS) as u64;

        // SSRF protection: validate URL and enforce host allowlist (same as HTTP fetch).
        let parsed_url: url::Url = url.parse().map_err(|_| wit_webhook::Error::Sendfailed)?;
        let host = parsed_url.host_str().unwrap_or("").to_string();

        // HTTPS-only by default. Webhook deliveries are the highest-
        // value plaintext target since they carry a signed payload
        // bound to a guest secret; intercepting the wire is enough to
        // replay it. Operator opt-in only.
        match classify_url_scheme(parsed_url.scheme(), insecure_http_opt_in()) {
            UrlSchemeVerdict::Https => {}
            UrlSchemeVerdict::InsecureAllowedByOptIn { scheme } => {
                tracing::warn!(
                    scheme = %scheme,
                    host = %host,
                    "webhook::send: insecure-scheme request allowed by WASM_ALLOW_INSECURE_HTTP=1"
                );
            }
            UrlSchemeVerdict::InsecureRefused { scheme } => {
                self.record_capability_denied(
                    "webhook",
                    "insecure-scheme",
                    &format!("{scheme} {host}"),
                )
                .await;
                tracing::warn!(
                    scheme = %scheme,
                    host = %host,
                    "WASM module attempted non-https webhook send — denied."
                );
                return Err(wit_webhook::Error::Sendfailed);
            }
        }

        // Enforce the host allowlist. Empty list means DENY ALL.
        if self.allowed_hosts.is_empty() {
            self.record_capability_denied("webhook", "no-allowlist-configured", &host)
                .await;
            tracing::warn!(
                host = %host,
                "WASM module attempted webhook request but no host allowlist is configured — denying."
            );
            return Err(wit_webhook::Error::Sendfailed);
        }

        // Block private/loopback/link-local IP addresses to prevent SSRF.
        // Shared classifier — covers CGNAT and IPv4-mapped IPv6 the
        // duplicated logic was missing.
        if let Some((ip, policy)) = denied_ip_literal(&parsed_url) {
            self.record_capability_denied("webhook", policy, &ip.to_string())
                .await;
            tracing::warn!(
                ip = %ip,
                policy,
                "WASM module attempted webhook to a private IP literal — blocking"
            );
            return Err(wit_webhook::Error::Sendfailed);
        }

        if !host_allowlist_match(&self.allowed_hosts, &host) {
            self.record_capability_denied("webhook", "allowed-hosts", &host)
                .await;
            tracing::warn!(
                host = %host,
                allowed_count = self.allowed_hosts.len(),
                "WASM module attempted webhook to a forbidden host"
            );
            return Err(wit_webhook::Error::Sendfailed);
        }

        // DNS rebinding — for hostname-based URLs, resolve and reject when
        // any answer falls in the private deny-list. Skipped for IP literals
        // (already handled by classify_private_ip above).
        if matches!(parsed_url.host(), Some(url::Host::Domain(_)))
            && self
                .validate_no_dns_rebinding(&host, "webhook")
                .await
                .is_err()
        {
            return Err(wit_webhook::Error::Sendfailed);
        }

        // Tier-1 LLM egress ceiling — webhook dispatch is yet another
        // arbitrary-host HTTP surface. Same deny-list applies.
        if matches!(
            self.max_llm_tier,
            talos_workflow_job_protocol::LlmTier::Tier1
        ) {
            let host_lower = host.to_ascii_lowercase();
            if let Some(policy) = tier1_egress_deny_reason(&host_lower) {
                self.record_capability_denied("webhook", policy, &host)
                    .await;
                tracing::warn!(
                    host = %host,
                    actor_id = ?self.actor_id,
                    policy,
                    "tier-1 actor webhook egress refused (external LLM host or public IP literal)"
                );
                return Err(wit_webhook::Error::Sendfailed);
            }
        }

        // MCP-537 (rate limit + cancellation): now charged AFTER all pure
        // validation has passed — see MCP-785 reorder comment at top of
        // this function.
        if !self.check_rate_limit(&self.webhook_send_count, MAX_WEBHOOK_SENDS_PER_EXECUTION) {
            tracing::warn!(module_id = ?self.module_id, "Webhook send rate limit exceeded");
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("webhook");
            }
            return Err(wit_webhook::Error::Sendfailed);
        }
        if self.is_cancelled() {
            tracing::info!(module_id = ?self.module_id, "Execution cancelled before webhook send");
            if let Some(ref m) = self.metrics {
                m.record_execution_cancelled();
            }
            return Err(wit_webhook::Error::Sendfailed);
        }

        // Dry-run mode: mock webhook POST calls
        if self.dry_run {
            tracing::info!(
                url = %url,
                "Dry-run: intercepted webhook send"
            );
            return Ok(wit_webhook::WebhookResponse {
                status: 200,
                body: serde_json::json!({
                    "__dry_run__": true,
                    "intercepted_method": "POST",
                    "intercepted_url": url,
                })
                .to_string(),
                retries: 0,
            });
        }

        let client = self.http_client.clone();

        let mut retries = 0u32;
        loop {
            let mut req_builder = client
                .post(&url)
                .body(body.clone())
                .timeout(std::time::Duration::from_secs(30));
            for (k, v) in &headers {
                let resolved = self
                    .resolve_vault_header(k.as_str(), v.as_str())
                    .await
                    .map_err(|_| wit_webhook::Error::Sendfailed)?;
                req_builder = req_builder.header(k.as_str(), resolved.as_ref());
            }

            match req_builder.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    tracing::info!(
                        method = "POST",
                        host = %parsed_url.host_str().unwrap_or("unknown"),
                        path = %parsed_url.path(),
                        status = status,
                        "HTTP audit"
                    );
                    const MAX_WEBHOOK_RESP_BYTES: usize = 1_000_000;
                    let mut bytes = Vec::new();
                    let mut stream = resp.bytes_stream();
                    use futures_util::StreamExt;
                    while let Some(chunk_result) = stream.next().await {
                        if let Ok(chunk) = chunk_result {
                            let remaining = MAX_WEBHOOK_RESP_BYTES.saturating_sub(bytes.len());
                            if remaining > 0 {
                                let take = chunk.len().min(remaining);
                                bytes.extend_from_slice(&chunk[..take]);
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    let body = String::from_utf8_lossy(&bytes).into_owned();
                    return Ok(wit_webhook::WebhookResponse {
                        status,
                        body,
                        retries,
                    });
                }
                Err(e) if retries < max_retries => {
                    retries += 1;
                    if e.is_timeout() {
                        return Err(wit_webhook::Error::Timeout);
                    }
                    // MCP-583: re-check cancellation between retries so
                    // worker shutdown / execution cancellation preempts
                    // a long retry-sleep loop. Pre-fix the loop only
                    // checked is_cancelled() at entry — a send that hit
                    // a transient transport error would sleep the full
                    // retry_delay_ms even after a shutdown signal.
                    if self.is_cancelled() {
                        tracing::info!(
                            module_id = ?self.module_id,
                            "Execution cancelled during webhook retry sleep"
                        );
                        if let Some(ref m) = self.metrics {
                            m.record_execution_cancelled();
                        }
                        return Err(wit_webhook::Error::Sendfailed);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(retry_delay_ms)).await;
                }
                Err(e) => {
                    return Err(if e.is_timeout() {
                        wit_webhook::Error::Timeout
                    } else {
                        wit_webhook::Error::Sendfailed
                    });
                }
            }
        }
    }
}
