//! `messaging` (NATS publish/request) and `events` (domain event
//! emission) host interfaces.

use super::*;

// ============================================================================
// Messaging (NATS)
// ============================================================================

impl wit_messaging::Host for TalosContext {
    async fn publish(
        &mut self,
        topic: String,
        payload: Vec<u8>,
    ) -> Result<(), wit_messaging::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result: Result<(), wit_messaging::Error> = async move {
            // Defense-in-depth: linker is primary enforcement, but verify capability.
            use crate::wit_inspector::CapabilityWorld;
            if !matches!(
                self.capability_world,
                CapabilityWorld::Messaging | CapabilityWorld::Trusted
            ) {
                self.record_capability_denied("messaging-publish", "capability-world", &topic)
                    .await;
                tracing::warn!(module_id = ?self.module_id, "WASM module attempted messaging but lacks Messaging capability");
                return Err(wit_messaging::Error::Publishfailed);
            }
            // MCP-756 (2026-05-13): cap topic length BEFORE it flows into
            // any logging / audit / NATS sink. See MAX_MESSAGING_TOPIC_BYTES
            // doc. Runs before the reserved-prefix check below so an
            // oversized "talos.<10MB>" topic doesn't poison the
            // reserved-prefix audit-deny path.
            if topic.is_empty() || topic.len() > MAX_MESSAGING_TOPIC_BYTES {
                tracing::warn!(
                    module_id = ?self.module_id,
                    topic_len = topic.len(),
                    "wit_messaging::publish topic exceeds {} bytes (or empty); rejecting",
                    MAX_MESSAGING_TOPIC_BYTES
                );
                return Err(wit_messaging::Error::Publishfailed);
            }
            // MCP-524: deny publish to reserved platform-internal
            // subject namespaces. The signed-RPC layer rejects forged
            // payloads (memory_rpc / graph_rpc / database_rpc /
            // state_rpc / integration_state_rpc all verify HMAC), but
            // each forged message still costs the controller a
            // signature-verification + error-log line. A guest that
            // loops `publish("talos.memory.op", b"garbage")` up to its
            // rate-limit cap (1000/exec) can quietly burn ~50ms of
            // controller CPU per execution + flood error logs.
            // Equally, `talos.results.*` (job-result subjects) and
            // `talos.workers.*` (heartbeat / cmd) are platform-owned —
            // a guest must never publish there.
            //
            // Modules should use their own subject namespace (e.g.
            // operator/team prefix). Same convention as the
            // module-allowlist for HTTP hosts.
            if reject_reserved_topic_prefix(&topic) {
                self.record_capability_denied(
                    "messaging-publish",
                    "reserved-subject-prefix",
                    &topic,
                )
                .await;
                tracing::warn!(
                    module_id = ?self.module_id,
                    topic = %topic,
                    "WASM module attempted to publish to a platform-reserved \
                     subject (talos.* / wasm.*) — denied. Use your own \
                     subject namespace."
                );
                return Err(wit_messaging::Error::Publishfailed);
            }
            // MCP-784 (2026-05-14): pure-validation payload-size check MUST
            // run BEFORE `check_rate_limit` charges the publish counter.
            // Pre-fix, a guest with Messaging capability could call
            // `publish(topic, vec![0u8; 10 * 1024 * 1024 + 1])` repeatedly —
            // each call passed capability/topic/reserved-prefix checks,
            // consumed one slot of MAX_MESSAGING_PUBLISHES_PER_EXECUTION
            // (1000/exec), and only then failed the 10 MB payload cap.
            // After 1000 oversized attempts the publish quota was
            // exhausted and legitimate small-payload publishes were
            // blocked for the rest of the execution, despite zero NATS
            // traffic. Same shape as MCP-770 (wit_files::write byte-quota
            // before path sanitize), MCP-783 (wit_http::fetch_all
            // batch-CAS before per-request validation), and MCP-612
            // (the original counter-only-advances-when-admitted rule).
            if payload.len() > 10 * 1024 * 1024 {
                tracing::warn!("Message payload exceeds 10MB limit");
                return Err(wit_messaging::Error::Publishfailed);
            }
            if !self.check_rate_limit(
                &self.messaging_publish_count,
                MAX_MESSAGING_PUBLISHES_PER_EXECUTION,
            ) {
                tracing::warn!(module_id = ?self.module_id, "Messaging publish rate limit exceeded");
                if let Some(ref m) = self.metrics {
                    m.record_rate_limit_exceeded("messaging");
                }
                return Err(wit_messaging::Error::Publishfailed);
            }

            // Dry-run mode: mock messaging publish
            if self.dry_run {
                tracing::info!(
                    topic = %topic,
                    payload_len = payload.len(),
                    "Dry-run: intercepted messaging publish"
                );
                return Ok(());
            }

            let nats = self
                .nats_client
                .as_ref()
                .ok_or(wit_messaging::Error::Connectionfailed)?;
            let nats = nats.clone();

            nats.publish(topic, payload.into())
                .await
                .map_err(|_| wit_messaging::Error::Publishfailed)
        }.await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call("messaging::publish", __start.elapsed().as_millis() as f64);
        }
        __result
    }

    async fn publish_with_headers(
        &mut self,
        msg: wit_messaging::Message,
    ) -> Result<(), wit_messaging::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Messaging | CapabilityWorld::Trusted
        ) {
            self.record_capability_denied("messaging-publish", "capability-world", &msg.topic)
                .await;
            tracing::warn!(module_id = ?self.module_id, "WASM module attempted messaging but lacks Messaging capability");
            return Err(wit_messaging::Error::Publishfailed);
        }
        // MCP-756: cap topic length, sibling-parity with `publish` above.
        if msg.topic.is_empty() || msg.topic.len() > MAX_MESSAGING_TOPIC_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                topic_len = msg.topic.len(),
                "wit_messaging::publish_with_headers topic exceeds {} bytes (or empty); rejecting",
                MAX_MESSAGING_TOPIC_BYTES
            );
            return Err(wit_messaging::Error::Publishfailed);
        }
        // MCP-524: same reserved-prefix denylist as the bare `publish`
        // path. Sibling helper invoked once per call.
        if reject_reserved_topic_prefix(&msg.topic) {
            self.record_capability_denied(
                "messaging-publish-with-headers",
                "reserved-subject-prefix",
                &msg.topic,
            )
            .await;
            tracing::warn!(
                module_id = ?self.module_id,
                topic = %msg.topic,
                "WASM module attempted to publish_with_headers to a \
                 platform-reserved subject — denied."
            );
            return Err(wit_messaging::Error::Publishfailed);
        }
        // MCP-784 (2026-05-14): payload-size validation BEFORE rate-limit
        // charge — see `publish` above for the full sibling-drift rationale.
        if msg.payload.len() > 10 * 1024 * 1024 {
            tracing::warn!("Message payload exceeds 10MB limit");
            return Err(wit_messaging::Error::Publishfailed);
        }
        if !self.check_rate_limit(
            &self.messaging_publish_count,
            MAX_MESSAGING_PUBLISHES_PER_EXECUTION,
        ) {
            tracing::warn!(module_id = ?self.module_id, "Messaging publish rate limit exceeded");
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("messaging");
            }
            return Err(wit_messaging::Error::Publishfailed);
        }

        // Dry-run mode: mock messaging publish_with_headers
        if self.dry_run {
            tracing::info!(
                topic = %msg.topic,
                payload_len = msg.payload.len(),
                "Dry-run: intercepted messaging publish_with_headers"
            );
            return Ok(());
        }

        let nats = self
            .nats_client
            .as_ref()
            .ok_or(wit_messaging::Error::Connectionfailed)?;
        let nats = nats.clone();

        let mut headers = async_nats::HeaderMap::new();
        if let Some(hdr_list) = msg.headers {
            // MCP-1105 sibling: cap header count BEFORE the per-header
            // vault-resolve loop. `resolve_vault_header` is a DB call
            // (cache hit common but not guaranteed); unbounded iteration
            // is the exact amplification `MAX_OUTBOUND_HEADERS = 64`
            // bounds on `wit_http::fetch`, `wit_webhook::send`, and
            // `wit_graphql::execute`. publish_with_headers was the
            // holdout.
            if hdr_list.len() > MAX_OUTBOUND_HEADERS {
                tracing::warn!(
                    module_id = ?self.module_id,
                    header_count = hdr_list.len(),
                    limit = MAX_OUTBOUND_HEADERS,
                    "wit_messaging::publish_with_headers rejected: header count exceeds cap"
                );
                return Err(wit_messaging::Error::Publishfailed);
            }
            for (k, v) in &hdr_list {
                let resolved = self
                    .resolve_vault_header(k.as_str(), v.as_str())
                    .await
                    .map_err(|_| wit_messaging::Error::Publishfailed)?;
                headers.insert(k.as_str(), resolved.as_ref());
            }
        }
        nats.publish_with_headers(msg.topic, headers, msg.payload.into())
            .await
            .map_err(|_| wit_messaging::Error::Publishfailed)
    }

    async fn request(
        &mut self,
        topic: String,
        payload: Vec<u8>,
        timeout_ms: u32,
    ) -> Result<Vec<u8>, wit_messaging::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Messaging | CapabilityWorld::Trusted
        ) {
            self.record_capability_denied("messaging-request", "capability-world", &topic)
                .await;
            tracing::warn!(module_id = ?self.module_id, "WASM module attempted messaging request but lacks Messaging capability");
            return Err(wit_messaging::Error::Subscribefailed);
        }
        // MCP-756: cap topic length, sibling-parity with `publish`.
        if topic.is_empty() || topic.len() > MAX_MESSAGING_TOPIC_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                topic_len = topic.len(),
                "wit_messaging::request topic exceeds {} bytes (or empty); rejecting",
                MAX_MESSAGING_TOPIC_BYTES
            );
            return Err(wit_messaging::Error::Publishfailed);
        }
        // MCP-731 (2026-05-13): apply the same reserved-topic deny that
        // `publish` (MCP-524) and `publish_with_headers` use. Pre-fix,
        // a guest with Messaging capability could call
        // `request("talos.memory.op", forged_payload)` and the worker
        // would forward the request to the controller's memory_rpc
        // subscriber. The HMAC verification rejects the forged
        // signature, but each forged message still costs the
        // controller a signature-verification + error log. Same
        // DoS vector MCP-524 closed for publish; the request variant
        // was missed in that sweep.
        if reject_reserved_topic_prefix(&topic) {
            self.record_capability_denied("messaging-request", "reserved-subject-prefix", &topic)
                .await;
            tracing::warn!(
                module_id = ?self.module_id,
                topic = %topic,
                "WASM module attempted to request() on a platform-reserved \
                 subject (talos.* / wasm.*) — denied. Use your own subject namespace."
            );
            return Err(wit_messaging::Error::Publishfailed);
        }
        // MCP-784 (2026-05-14): payload-size validation BEFORE rate-limit
        // charge — see `publish` above for the full sibling-drift rationale.
        // The 10MB outbound payload cap (MCP-731) is pure validation; it
        // must precede the messaging_publish_count CAS so that oversized
        // requests don't drain MAX_MESSAGING_PUBLISHES_PER_EXECUTION.
        if payload.len() > 10 * 1024 * 1024 {
            tracing::warn!(
                module_id = ?self.module_id,
                payload_len = payload.len(),
                "Messaging request payload exceeds 10MB limit"
            );
            return Err(wit_messaging::Error::Publishfailed);
        }
        if !self.check_rate_limit(
            &self.messaging_publish_count,
            MAX_MESSAGING_PUBLISHES_PER_EXECUTION,
        ) {
            tracing::warn!(module_id = ?self.module_id, "Messaging request rate limit exceeded");
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("messaging");
            }
            return Err(wit_messaging::Error::Publishfailed);
        }
        let nats = self
            .nats_client
            .as_ref()
            .ok_or(wit_messaging::Error::Connectionfailed)?;
        let nats = nats.clone();

        // MCP-657: clamp caller-supplied timeout. Guest can pass
        // u32::MAX which would hold a worker task ~49 days awaiting a
        // never-arriving NATS reply. async fuel is observation-only
        // so the wasm budget doesn't naturally bound this. Sibling
        // pattern to MCP-583/584 for http/webhook retry caps.
        let bounded_timeout_ms = timeout_ms.min(MAX_MESSAGING_REQUEST_TIMEOUT_MS);
        let reply = tokio::time::timeout(
            std::time::Duration::from_millis(bounded_timeout_ms as u64),
            nats.request(topic, payload.into()),
        )
        .await
        .map_err(|_| wit_messaging::Error::Publishfailed)?
        .map_err(|_| wit_messaging::Error::Publishfailed)?;
        // MCP-731 sibling: cap inbound reply size. Without this, a
        // collaborating NATS-side service (or a future bug that lets
        // the guest control reply contents) could return GBs of data
        // and the guest's `to_vec()` would copy it into WASM linear
        // memory unbounded. 10MB matches the outbound cap and the
        // sibling wit_http response cap.
        if reply.payload.len() > 10 * 1024 * 1024 {
            tracing::warn!(
                module_id = ?self.module_id,
                reply_len = reply.payload.len(),
                "Messaging request reply exceeds 10MB limit; rejecting"
            );
            return Err(wit_messaging::Error::Publishfailed);
        }
        Ok(reply.payload.to_vec())
    }
}

// ============================================================================
// Events (structured domain event emission)
// ============================================================================

impl wit_events::Host for TalosContext {
    async fn emit(&mut self, event_type: String, payload: String) -> Result<(), wit_events::Error> {
        self.emit_with_metadata(event_type, payload, None).await
    }

    async fn emit_with_metadata(
        &mut self,
        event_type: String,
        payload: String,
        metadata: Option<String>,
    ) -> Result<(), wit_events::Error> {
        use crate::wit_inspector::CapabilityWorld;
        if matches!(
            self.capability_world,
            CapabilityWorld::Minimal | CapabilityWorld::Unknown
        ) {
            // MCP-697 (2026-05-13): audit-ledger parity (sibling of MCP-696
            // wit_cache sweep). Pre-fix this branch returned
            // `Error::RateLimited` (semantically misleading — it's NOT a
            // rate-limit denial, it's a capability denial) with no audit
            // event. Operators watching `talos.audit.ledger` for the
            // wasi:capability_denied event class missed every probe of
            // the events surface. Emit the audit BEFORE the early return
            // so the WORM trail captures the attempt.
            self.record_capability_denied("events-emit", "capability-world", &event_type)
                .await;
            return Err(wit_events::Error::RateLimited);
        }
        // MCP-790 (2026-05-14): pure-validation surfaces (event_type
        // charset + length, payload size cap, metadata size cap) MUST
        // run BEFORE `check_rate_limit` charges `event_emit_count`.
        // Pre-fix the rate-limit charge ran first, so a Database/Trusted-
        // world guest could drain MAX_EVENTS_PER_EXECUTION (100/exec)
        // by looping emit("event with spaces" or "talos.x.x.x x")
        // (InvalidEventType) or oversized payloads (PayloadTooLarge),
        // with zero events ever reaching NATS or the audit ledger.
        // Subsequent legitimate emits were blocked for the rest of the
        // execution. emit() (the no-metadata variant) delegates here,
        // so the same drain applied via both entry points. Final
        // identified site in the sweep started at MCP-783; same shape
        // as MCP-770/783/784/785/786/787/788/789 and MCP-612 (counter-
        // only-advances-when-admitted).
        // Validate event type: alphanumeric, dots, hyphens, underscores only.
        if event_type.is_empty()
            || event_type.len() > 256
            || !event_type
                .chars()
                .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return Err(wit_events::Error::InvalidEventType);
        }
        if payload.len() > MAX_EVENT_PAYLOAD_BYTES {
            return Err(wit_events::Error::PayloadTooLarge);
        }
        // MCP-600 (2026-05-12): pre-dispatch cap on `metadata`. Reuse
        // `PayloadTooLarge` so the guest gets a single recognisable
        // error variant for "your event was rejected for size"
        // regardless of which field exceeded — keeps the guest-side
        // error handling shape simple.
        if let Some(md) = metadata.as_deref() {
            if md.len() > MAX_EVENT_METADATA_BYTES {
                return Err(wit_events::Error::PayloadTooLarge);
            }
        }
        if !self.check_rate_limit(&self.event_emit_count, MAX_EVENTS_PER_EXECUTION) {
            tracing::warn!(module_id = ?self.module_id, "Event emit rate limit exceeded");
            return Err(wit_events::Error::RateLimited);
        }

        let exec_id = self
            .execution_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        let event_json = serde_json::json!({
            "event_type": event_type,
            "payload": payload,
            "metadata": metadata,
            "execution_id": exec_id,
            "module_id": self.module_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        // Best-effort publish — events don't fail the module if NATS is down.
        if let Some(nats) = &self.nats_client {
            let topic = format!("talos.events.{}.{}", exec_id, event_type);
            if let Ok(payload_bytes) = serde_json::to_vec(&event_json) {
                let _ = nats.publish(topic, payload_bytes.into()).await;
            }
        } else {
            tracing::debug!(
                event_type,
                "events::emit called but NATS not available — event not published"
            );
        }

        Ok(())
    }
}
