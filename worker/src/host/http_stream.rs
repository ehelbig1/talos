//! `http-stream` (SSE consumption) host interface.

use super::*;

// ============================================================================
// HTTP Stream (SSE consumption)
// ============================================================================

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
            return Err(wit_http_stream::Error::ForbiddenHost);
        }
        if self.is_cancelled() {
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
            return Err(wit_http_stream::Error::InvalidUrl);
        }

        // Enforce concurrent stream cap.
        {
            let streams = self
                .streams
                .sse
                .lock()
                .map_err(|_| wit_http_stream::Error::ConnectionFailed)?;
            if streams.len() >= MAX_SSE_STREAMS_PER_EXECUTION {
                tracing::warn!(
                    module_id = ?self.module_id,
                    active = streams.len(),
                    "SSE stream limit reached ({} max)",
                    MAX_SSE_STREAMS_PER_EXECUTION
                );
                return Err(wit_http_stream::Error::RateLimited);
            }
        }

        // Parse and validate URL (same SSRF protections as http::fetch).
        let parsed: url::Url = url
            .parse()
            .map_err(|_| wit_http_stream::Error::InvalidUrl)?;

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
                return Err(wit_http_stream::Error::InvalidUrl);
            }
        }

        if self.allowed_hosts.is_empty() {
            self.record_capability_denied("http-stream", "no-allowlist-configured", &host)
                .await;
            return Err(wit_http_stream::Error::ForbiddenHost);
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
            return Err(wit_http_stream::Error::ForbiddenHost);
        }
        if !host_allowlist_match(&self.allowed_hosts, &host) {
            self.record_capability_denied("http-stream", "allowed-hosts", &host)
                .await;
            return Err(wit_http_stream::Error::ForbiddenHost);
        }

        // DNS rebinding — same shared check used by fetch / webhook / graphql.
        if matches!(parsed.host(), Some(url::Host::Domain(_)))
            && self
                .validate_no_dns_rebinding(&host, "http-stream")
                .await
                .is_err()
        {
            return Err(wit_http_stream::Error::ForbiddenHost);
        }

        // Tier-1 LLM egress ceiling — SSE stream to an external LLM
        // would exfiltrate via streaming-response reads. Deny here too.
        if matches!(
            self.max_llm_tier,
            talos_workflow_job_protocol::LlmTier::Tier1
        ) {
            let host_lower = host.to_ascii_lowercase();
            if let Some(policy) = tier1_egress_deny_reason(&host_lower) {
                self.record_capability_denied("http-stream", policy, &host)
                    .await;
                tracing::warn!(
                    host = %host,
                    actor_id = ?self.actor_id,
                    policy,
                    "tier-1 actor HTTP stream egress refused (external LLM host or public IP literal)"
                );
                return Err(wit_http_stream::Error::ForbiddenHost);
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
            return Err(wit_http_stream::Error::RateLimited);
        }

        let (tx, rx) = tokio::sync::mpsc::channel::<crate::context::SseEventInternal>(1_000);
        let stream_id = uuid::Uuid::new_v4().to_string();

        {
            let mut streams = self
                .streams
                .sse
                .lock()
                .map_err(|_| wit_http_stream::Error::ConnectionFailed)?;
            streams.insert(stream_id.clone(), rx);
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
            return Err(wit_http_stream::Error::ForbiddenHost);
        }
        // Resolve vault:// headers.
        let resolved_headers: Vec<(String, String)> = {
            let mut hdrs = Vec::with_capacity(headers.len());
            for (k, v) in &headers {
                let resolved = self
                    .resolve_vault_header(k.as_str(), v.as_str())
                    .await
                    .map_err(|_| wit_http_stream::Error::ForbiddenHost)?;
                hdrs.push((k.clone(), resolved.into_owned()));
            }
            hdrs
        };

        let client = self.http_client.clone();
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

        tokio::spawn(async move {
            let mut req_builder = client
                .get(&url_owned)
                .header("Accept", "text/event-stream")
                .header("Cache-Control", "no-cache");
            for (k, v) in &resolved_headers {
                req_builder = req_builder.header(k.as_str(), v.as_str());
            }

            // MCP-721 (2026-05-13): cap the initial connection-establishment
            // phase at 30 s. Pre-fix `req_builder.send().await` had no
            // timeout — if the SSE server stalled (never sent response
            // headers), this spawned task hung indefinitely waiting. The
            // guest's `cancel_stream` / `close` only signal via the `tx`/`rx`
            // channel, which the task only checks on each `tx.send()` AFTER
            // headers arrive — meaning a stall before headers leaks the
            // task forever. SSE legitimately needs long-lived bodies, so
            // ONLY the initial send is timed-out here; the bytes_stream
            // loop below remains unbounded (intended for streaming).
            const SSE_CONNECT_TIMEOUT_SECS: u64 = 30;
            let response = match tokio::time::timeout(
                std::time::Duration::from_secs(SSE_CONNECT_TIMEOUT_SECS),
                req_builder.send(),
            )
            .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "SSE connection failed");
                    return;
                }
                Err(_) => {
                    tracing::warn!(
                        url = %url_owned,
                        timeout_secs = SSE_CONNECT_TIMEOUT_SECS,
                        "SSE connection timed out before response headers"
                    );
                    return;
                }
            };

            if !response.status().is_success() {
                tracing::warn!(
                    status = response.status().as_u16(),
                    "SSE endpoint returned error"
                );
                return;
            }

            // Parse SSE stream: accumulate lines, emit on blank lines.
            //
            // SECURITY: cap both the incoming-byte buffer and the
            // per-event accumulated data. A misbehaving server that
            // never emits a blank line would otherwise grow `data_lines`
            // monotonically until the worker OOMs. Likewise, an attacker
            // streaming a single huge line with no `\n` could grow
            // `buffer` unbounded. Both caps are 1 MiB by default; set
            // TALOS_SSE_MAX_EVENT_BYTES to override per-deploy.
            // MCP-670: `=0`-safe env helper. `TALOS_SSE_MAX_EVENT_BYTES=0`
            // would abort every SSE stream on the first received byte
            // (`buffer.len() > 0` is true immediately), so the whole
            // streaming surface silently breaks under helm misconfig.
            const DEFAULT_SSE_MAX_BYTES: usize = 1024 * 1024;
            let max_event_bytes: usize = talos_config::positive_env_or_default::<usize>(
                "TALOS_SSE_MAX_EVENT_BYTES",
                DEFAULT_SSE_MAX_BYTES,
            );

            let mut stream = response.bytes_stream();
            let mut buffer = String::new();
            let mut event_type: Option<String> = None;
            let mut data_lines: Vec<String> = Vec::new();
            let mut data_bytes: usize = 0;
            let mut event_id: Option<String> = None;

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
                            return;
                        }
                        continue;
                    }
                };
                let chunk_result = match chunk_result {
                    Some(c) => c,
                    None => break,
                };
                let chunk = match chunk_result {
                    Ok(c) => c,
                    Err(_) => break,
                };
                buffer.push_str(&String::from_utf8_lossy(&chunk));

                if buffer.len() > max_event_bytes {
                    tracing::warn!(
                        url = %url_owned,
                        max_bytes = max_event_bytes,
                        actual_bytes = buffer.len(),
                        "SSE buffer exceeded max event size with no newline; aborting stream"
                    );
                    return;
                }

                while let Some(nl_pos) = buffer.find('\n') {
                    let line = buffer[..nl_pos].trim_end_matches('\r').to_string();
                    buffer = buffer[nl_pos + 1..].to_string();

                    if line.is_empty() {
                        // Blank line = event boundary
                        if !data_lines.is_empty() {
                            let event = crate::context::SseEventInternal {
                                event_type: event_type.take(),
                                data: data_lines.join("\n"),
                                id: event_id.take(),
                            };
                            if tx.send(event).await.is_err() {
                                return; // Receiver dropped (close called)
                            }
                            data_lines.clear();
                            data_bytes = 0;
                        }
                    } else if let Some(value) = line.strip_prefix("data:") {
                        let v = value.trim_start().to_string();
                        data_bytes = data_bytes.saturating_add(v.len()).saturating_add(1);
                        if data_bytes > max_event_bytes {
                            tracing::warn!(
                                url = %url_owned,
                                max_bytes = max_event_bytes,
                                accumulated_bytes = data_bytes,
                                "SSE event data exceeded max size before blank-line boundary; aborting stream"
                            );
                            return;
                        }
                        data_lines.push(v);
                    } else if let Some(value) = line.strip_prefix("event:") {
                        event_type = Some(value.trim_start().to_string());
                    } else if let Some(value) = line.strip_prefix("id:") {
                        event_id = Some(value.trim_start().to_string());
                    }
                    // Skip comments (lines starting with :) and retry: fields
                }
            }
        });

        Ok(stream_id)
    }

    async fn next_event(&mut self, stream_id: String) -> Option<wit_http_stream::SseEvent> {
        // Take the receiver out so we don't hold the mutex during await.
        let mut rx = {
            let mut streams = self.streams.sse.lock().ok()?;
            streams.remove(&stream_id)?
        };

        let event = rx.recv().await;

        // Put back if we got an event; if None (channel closed), stream is done.
        if event.is_some() {
            if let Ok(mut streams) = self.streams.sse.lock() {
                streams.insert(stream_id, rx);
            }
        }

        event.map(|e| wit_http_stream::SseEvent {
            event_type: e.event_type,
            data: e.data,
            id: e.id,
        })
    }

    async fn close(&mut self, stream_id: String) {
        // Removing the receiver causes the spawned task's tx.send() to fail,
        // which makes it exit cleanly.
        if let Ok(mut streams) = self.streams.sse.lock() {
            streams.remove(&stream_id);
        }
    }
}
