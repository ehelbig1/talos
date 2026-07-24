//! `email` host interface (SendGrid-compatible HTTP API).

use super::*;

// ============================================================================
// Email (HTTP API — SendGrid-compatible; provide EMAIL_API_URL + EMAIL_API_KEY)
// ============================================================================

impl wit_email::Host for TalosContext {
    async fn send(&mut self, msg: wit_email::Message) -> Result<(), wit_email::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result: Result<(), wit_email::Error> = async move {
        // MCP-786 (2026-05-14): pure-validation surfaces (Tier-1 egress
        // ceiling, recipient address validation, msg.to non-empty,
        // recipient count cap) MUST run BEFORE `check_rate_limit` charges
        // `email_send_count`. Pre-fix the rate-limit charge ran first,
        // so a tier-1 actor could loop send() up to
        // MAX_EMAIL_SENDS_PER_EXECUTION (50/exec) times — every call
        // refused at the Tier-1 gate but still consumed a slot — and any
        // guest could drain the quota with addresses containing CRLF
        // injection (Invalidaddress) or oversized recipient lists. After
        // 50 drained attempts, legitimate email sends were blocked for
        // the rest of the execution despite zero outbound API calls.
        // Same shape as MCP-770 (wit_files::write byte-CAS before path
        // sanitize), MCP-783 (wit_http::fetch_all batch-CAS before
        // per-request validation), MCP-784 (wit_messaging payload-size
        // after rate-limit), MCP-785 (wit_webhook::send rate-limit
        // before URL/SSRF/allowlist/DNS-rebind/Tier-1), and MCP-612
        // (the original counter-only-advances-when-admitted rule).
        // MCP-523 (the original rate-limit add) is preserved — only the
        // ordering moves; cancellation check also relocates to stay
        // paired with the rate-limit charge.

        // Tier-1 enforcement: tier-1 actors carry a "data must not leave
        // host" privacy ceiling. Email is by definition external data
        // egress (recipient addresses + subject + body all flow to a
        // third-party API), so refuse outright — sixth tier-1 surface
        // alongside wit_http::fetch / fetch_all, wit_graphql::execute,
        // wit_webhook::send, and wit_http_stream::connect. EMAIL_API_URL
        // is operator-set so a host-allowlist check would be redundant;
        // the privacy ceiling forbids the operation, not just the host.
        if matches!(
            self.max_llm_tier,
            talos_workflow_job_protocol::LlmTier::Tier1
        ) {
            self.record_capability_denied("email-send", "tier1-egress", "")
                .await;
            tracing::warn!(
                actor_id = ?self.actor_id,
                "tier-1 actor attempted wit_email::send; refused"
            );
            return Err(wit_email::Error::Sendfailed);
        }

        // Write-ceiling gate: sending email is an outbound mutation — refuse
        // for read-only actors. Target is empty (recipient addresses are PII
        // and must not enter the WORM ledger). Inert unless enforcement is on.
        if self.write_ceiling_refuses("email-send", "").await {
            return Err(wit_email::Error::Unauthorized);
        }

        // Validate recipient addresses.
        // SECURITY: Reject control characters (CR, LF, NUL) to prevent email
        // header injection attacks (e.g., "victim@example.com\r\nBcc: attacker@evil.com").
        for addr in &msg.to {
            if !addr.contains('@') || addr.len() > 320
                || addr.bytes().any(|b| b < 0x20 || b == 0x7f)
            {
                return Err(wit_email::Error::Invalidaddress);
            }
        }
        // Also validate CC and BCC recipients for the same injection attacks.
        for addr in msg.cc.iter().flatten().chain(msg.bcc.iter().flatten()) {
            if !addr.contains('@') || addr.len() > 320
                || addr.bytes().any(|b| b < 0x20 || b == 0x7f)
            {
                return Err(wit_email::Error::Invalidaddress);
            }
        }
        if msg.to.is_empty() {
            return Err(wit_email::Error::Invalidaddress);
        }

        // MCP-541: cap ALL recipients (to + cc + bcc), not just `to`. The
        // MCP-523 design comment on `MAX_EMAIL_SENDS_PER_EXECUTION` (50)
        // promises a worst-case fanout of "50×50 = 2500 deliveries per
        // execution" — that math assumes 50 is the per-MESSAGE recipient
        // cap. Pre-fix only `msg.to.len()` was checked, so a WASM module
        // could pack 50 `to` + thousands of `cc`/`bcc` recipients per
        // message and blow through the operator's third-party send
        // quota (SendGrid bills per recipient). CC/BCC are still
        // egress and still cost the operator the same per-recipient
        // billing — they must be counted against the same cap.
        let cc_count = msg.cc.as_ref().map(|c| c.len()).unwrap_or(0);
        let bcc_count = msg.bcc.as_ref().map(|c| c.len()).unwrap_or(0);
        let total_recipients = msg.to.len() + cc_count + bcc_count;
        if total_recipients > MAX_EMAIL_RECIPIENTS_PER_MESSAGE {
            tracing::warn!(
                module_id = ?self.module_id,
                to = msg.to.len(),
                cc = cc_count,
                bcc = bcc_count,
                total = total_recipients,
                cap = MAX_EMAIL_RECIPIENTS_PER_MESSAGE,
                "Email recipient count (to + cc + bcc) exceeds limit"
            );
            return Err(wit_email::Error::Sendfailed);
        }

        // MCP-1014 sibling: cap caller-supplied subject + body + html +
        // attachments byte size. Pre-fix `msg.body`, `msg.html`,
        // `msg.subject` were unbounded — a guest with the Email
        // capability could pack 10 MB-each strings into a single send,
        // materialise them into a `serde_json::Value`, then reqwest.
        // The post-MCP-1014 audit (2026-05-28 F1) caught that
        // `msg.attachments: Option<list<attachment>>` (per-attachment
        // `data: list<u8>`) was NOT counted toward the cap, so the
        // wit_email path still permitted megabyte-scale outbound
        // content via attachment data. The cap now sums all
        // recipient-billed content. With
        // MAX_EMAIL_SENDS_PER_EXECUTION=50, worst-case in-flight host
        // memory is bounded to ~500 MB per execution. Run AFTER the
        // validation/recipient gates so a malformed-recipient probe
        // doesn't burn the body-size check budget either way.
        const MAX_EMAIL_CONTENT_BYTES: usize = MAX_OUTBOUND_HTTP_BODY_BYTES;
        let html_len = msg.html.as_ref().map(|h| h.len()).unwrap_or(0);
        let attachments_count = msg.attachments.as_ref().map(|a| a.len()).unwrap_or(0);
        let attachments_bytes: usize = msg
            .attachments
            .as_ref()
            .map(|atts| {
                atts.iter()
                    .map(|a| a.filename.len() + a.content_type.len() + a.data.len())
                    .sum()
            })
            .unwrap_or(0);
        let body_bytes = msg.subject.len() + msg.body.len() + html_len + attachments_bytes;
        if body_bytes > MAX_EMAIL_CONTENT_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                subject_len = msg.subject.len(),
                body_len = msg.body.len(),
                html_len = html_len,
                attachments_count,
                attachments_bytes,
                total = body_bytes,
                cap = MAX_EMAIL_CONTENT_BYTES,
                "wit_email::send rejected: subject+body+html+attachments exceeds cap"
            );
            return Err(wit_email::Error::Sendfailed);
        }
        // Bound the attachment COUNT independently so a guest can't
        // ship 100k 1-byte attachments to exhaust SendGrid's per-call
        // limits (typical providers cap at 10 MB total / ~10 files).
        const MAX_EMAIL_ATTACHMENTS: usize = 32;
        if attachments_count > MAX_EMAIL_ATTACHMENTS {
            tracing::warn!(
                module_id = ?self.module_id,
                attachments_count,
                cap = MAX_EMAIL_ATTACHMENTS,
                "wit_email::send rejected: attachment count exceeds cap"
            );
            return Err(wit_email::Error::Sendfailed);
        }

        // MCP-523 (rate limit + cancellation): now charged AFTER all pure
        // validation has passed — see MCP-786 reorder comment at top of
        // this function.
        if !self.check_rate_limit(&self.email_send_count, MAX_EMAIL_SENDS_PER_EXECUTION) {
            tracing::warn!(module_id = ?self.module_id, "Email send rate limit exceeded");
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("email");
            }
            return Err(wit_email::Error::Sendfailed);
        }
        if self.is_cancelled() {
            tracing::info!(module_id = ?self.module_id, "Execution cancelled");
            if let Some(ref m) = self.metrics {
                m.record_execution_cancelled();
            }
            return Err(wit_email::Error::Sendfailed);
        }

        // Look up API credentials via SecretProvider first, then env vars.
        //
        // MCP-935 (2026-05-15): filter empty-string env values so a
        // Helm-placeholder `EMAIL_API_URL=""` or `EMAIL_API_KEY=""`
        // doesn't shadow a working fallback (or, worse, propagate an
        // empty string into the SendGrid request as a malformed URL
        // / Authorization header). The SecretProvider path
        // (`get_host_secret`) already applies this filter internally
        // at host_impl.rs:1202; the env-var fallback below was the
        // drift. Sibling sites at host_impl.rs:1302 and 1328 already
        // use the canonical `.ok().filter(|v| !v.is_empty())` shape.
        // Same empty-env-var-bypass class as MCP-590..631 / MCP-934.
        let api_url: Option<String> = self
            .get_host_secret("EMAIL_API_URL")
            .await
            .or_else(|| {
                std::env::var("EMAIL_API_URL")
                    .ok()
                    .filter(|v| !v.is_empty())
            });
        let api_key: Option<String> = self
            .get_host_secret("EMAIL_API_KEY")
            .await
            .or_else(|| {
                std::env::var("EMAIL_API_KEY")
                    .ok()
                    .filter(|v| !v.is_empty())
            });

        if let (Some(url), Some(key)) = (api_url, api_key) {
            // SendGrid v3 API format
            // MCP-631: empty-env hardening — `EMAIL_FROM=""` (Helm
            // placeholder) would otherwise produce an empty sender
            // address and SendGrid rejects the API call. Sibling to
            // MCP-630; worker is intentionally credential-free so the
            // helper is inlined here.
            let from = std::env::var("EMAIL_FROM")
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "noreply@talos.dev".to_string());

            let personalizations = serde_json::json!([{
                "to": msg.to.iter().map(|a| serde_json::json!({"email": a})).collect::<Vec<_>>(),
                "cc": msg.cc.as_ref().map(|cc| cc.iter().map(|a| serde_json::json!({"email": a})).collect::<Vec<_>>()),
                "bcc": msg.bcc.as_ref().map(|bcc| bcc.iter().map(|a| serde_json::json!({"email": a})).collect::<Vec<_>>()),
            }]);

            let mut content = vec![serde_json::json!({
                "type": "text/plain",
                "value": msg.body,
            })];
            if let Some(ref html) = msg.html {
                content.push(serde_json::json!({
                    "type": "text/html",
                    "value": html,
                }));
            }

            let body = serde_json::json!({
                "personalizations": personalizations,
                "from": {"email": from},
                "subject": msg.subject,
                "content": content,
            });

            let client = self.http_client.clone();
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                client
                    .post(&url)
                    .header("Authorization", format!("Bearer {}", key))
                    .header("Content-Type", "application/json")
                    .json(&body)
                    .send(),
            )
            .await
            .map_err(|_| {
                tracing::warn!("Email API request timed out");
                wit_email::Error::Sendfailed
            })?
            .map_err(|e| {
                tracing::warn!(error = %e, "Email API request failed");
                wit_email::Error::Sendfailed
            })?;

            if !response.status().is_success() {
                tracing::warn!(
                    status = response.status().as_u16(),
                    "Email API returned error status"
                );
                return Err(wit_email::Error::Sendfailed);
            }

            tracing::info!(
                to_count = msg.to.len(),
                subject_len = msg.subject.len(),
                "Email sent successfully via API"
            );
            return Ok(());
        }

        // Fallback: log the email if no API configured.
        //
        // MCP-1011 (2026-05-15): project recipient count + subject length
        // only — never the raw recipient list or subject content. Pre-fix
        // `tracing::info!(to = ?msg.to, subject = msg.subject, ...)` emitted
        // the full recipient PII + subject contents at INFO level. The
        // comment said "development mode" but the code path fires in
        // production any time `EMAIL_API_URL` is unset (Helm placeholder
        // forgotten, env-var rename, Vault outage during boot). Subject
        // lines routinely carry sensitive content — MFA codes, password-
        // reset links, "Your invoice is ready" with attached PII — and the
        // recipient list IS PII. Operator-log persistence of that content
        // for any misconfigured production tenant is a silent compliance
        // hit (GDPR, HIPAA, SOC 2 audit trail).
        //
        // Mirror the success-path projection at line 5295 exactly:
        // `to_count` + `subject_len`. Same MCP-852 / MCP-853 / MCP-854 /
        // MCP-921 family — field-projected logs over `{:?}` whole-struct
        // dumps for user-controlled content.
        tracing::info!(
            to_count = msg.to.len(),
            subject_len = msg.subject.len(),
            "[WASM email] Email send requested (no EMAIL_API_URL configured — logging only)"
        );
        Ok(())
        }.await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call("email::send", __start.elapsed().as_millis() as f64);
        }
        __result
    }
}
