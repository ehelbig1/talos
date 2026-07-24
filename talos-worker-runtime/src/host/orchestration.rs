//! `agent-orchestration` host interface and the signed agent NATS
//! envelope (build + verify).

use super::*;

// ============================================================================
// Agent Orchestration
// ============================================================================

/// Cap on per-field payload bytes when an agent message is built. The host
/// stamps `source_module` / `source_execution` itself (UUIDs); the only
/// guest-controlled blobs are `payload`, `correlation_id`, and `target`. The
/// total NATS payload after the signed envelope wrap is bounded by these
/// caps + ~512 bytes of envelope overhead.
///
/// Wasm-security review 2026-05-23 (H-4): pre-fix the payload field was an
/// unbounded JSON object; combined with the absence of HMAC signing, a
/// guest with the routine Agent capability could blast 100MB messages into
/// every `talos.agent.*` subscriber. Caps + signed envelope close both
/// arms in one change.
const MAX_AGENT_PAYLOAD_BYTES: usize = 64 * 1024;
/// Cap on the guest-supplied `correlation_id` envelope field, from the
/// same H-4 review as `MAX_AGENT_PAYLOAD_BYTES`. The WIT type is
/// `option<string>`, not a naturally-bounded u64 as the original
/// call-site comment assumed, so an unbounded value would flow into the
/// signed envelope, logs, and the response. Enforced fail-closed (reject,
/// never truncate — truncating a correlation identifier silently breaks
/// the guest's request/response matching) in `invoke` and `send`.
const MAX_AGENT_CORRELATION_ID_BYTES: usize = 256;

/// H-4: byte-length cap check for the guest-supplied `correlation_id`.
/// `None` always passes; `Some` passes iff its UTF-8 byte length is
/// within `MAX_AGENT_CORRELATION_ID_BYTES`. Byte-based (not char-based)
/// because the cap bounds the NATS envelope size. Pure function so the
/// boundary is unit-testable without a live host context.
fn correlation_id_exceeds_cap(correlation_id: &Option<String>) -> bool {
    correlation_id
        .as_ref()
        .is_some_and(|cid| cid.len() > MAX_AGENT_CORRELATION_ID_BYTES)
}

/// Build the signed NATS envelope for an agent invocation / message.
///
/// Wraps the guest-supplied payload in a versioned envelope and stamps it
/// with an HMAC-SHA256 signature bound to (subject, actor_id, nonce,
/// canonical_body). Subscribers under `talos.agent.*` MUST verify before
/// acting on the contents — see verification helper below.
///
/// Envelope shape (versioned for forward compatibility):
/// ```json
/// {
///   "v": 1,
///   "nonce": "<unix_ms>:<16 random hex bytes>",
///   "subject": "talos.agent.<target>.invoke",
///   "source_module": "<uuid|null>",
///   "source_execution": "<exec_id|null>",
///   "source_actor": "<uuid|nil>",
///   "source_worker": "<worker_id>",
///   "payload": <guest-supplied json>,
///   "correlation_id": <string|null>,
///   "signature": "<hex>"
/// }
/// ```
///
/// The signature covers `serde_json::to_vec(&envelope_without_signature)`
/// — the canonical body — combined with `subject`, `actor_id`, and
/// `nonce` per `talos_memory::rpc_auth::sign`. When the worker's HMAC key
/// isn't registered (test fixtures, dev without env), `signature` is
/// emitted as the empty string; production subscribers MUST refuse such
/// envelopes.
fn build_signed_agent_envelope(
    subject: &str,
    actor_id: Option<uuid::Uuid>,
    source_worker: &str,
    source_module: &Option<String>,
    source_execution: &Option<String>,
    payload: &serde_json::Value,
    correlation_id: &Option<String>,
) -> Result<Vec<u8>, &'static str> {
    use rand::Rng;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system time before epoch")?
        .as_millis();
    let rand_bytes: [u8; 16] = rand::thread_rng().gen();
    let nonce = format!("{}:{}", ts, hex::encode(rand_bytes));

    // Canonical envelope WITHOUT signature (which is added last). This is
    // the byte string we sign. Field-name ordering follows
    // `serde_json::json!` (preserves insertion order in this crate
    // version), so the canonical bytes are deterministic for a given
    // input.
    let envelope = serde_json::json!({
        "v": 1u32,
        "nonce": nonce,
        "subject": subject,
        "source_module": source_module,
        "source_execution": source_execution,
        // `source_actor` is the actor's identity claim (HMAC-bound on
        // the worker side); subscribers can pin against the actor's
        // expected_caller_actor_id field for additional defense.
        "source_actor": actor_id.unwrap_or(uuid::Uuid::nil()).to_string(),
        "source_worker": source_worker,
        "payload": payload,
        "correlation_id": correlation_id,
    });
    let canonical_body = serde_json::to_vec(&envelope).map_err(|_| "envelope serialise failed")?;

    // `rpc_auth::sign` returns None when the worker's HMAC key isn't
    // registered — that happens in unit tests and in pre-startup paths.
    // The envelope still goes on the wire (without signing); the
    // production subscriber's `MUST verify` rule covers refusal in that
    // case.
    let signature = talos_memory::rpc_auth::sign(
        subject,
        actor_id.unwrap_or(uuid::Uuid::nil()),
        &nonce,
        &canonical_body,
    )
    .map(hex::encode)
    .unwrap_or_default();

    // Now re-emit the envelope with the signature appended. We re-build
    // the JSON rather than splicing into the existing bytes to keep
    // the canonical body construction simple — subscribers do the same:
    // strip `signature`, recompute canonical body, verify.
    let signed = serde_json::json!({
        "v": 1u32,
        "nonce": nonce,
        "subject": subject,
        "source_module": source_module,
        "source_execution": source_execution,
        "source_actor": actor_id.unwrap_or(uuid::Uuid::nil()).to_string(),
        "source_worker": source_worker,
        "payload": payload,
        "correlation_id": correlation_id,
        "signature": signature,
    });
    serde_json::to_vec(&signed).map_err(|_| "signed envelope serialise failed")
}

/// Verify a signed agent NATS envelope. Documented public helper that
/// future `talos.agent.*` subscribers will call before acting on the
/// payload. Returns `Ok(payload)` when:
/// - the envelope JSON parses and has all required fields;
/// - `subject` matches the envelope's `subject` (defense against
///   re-publication onto a different topic);
/// - the freshness window holds (per `talos_memory::rpc_auth`);
/// - the HMAC signature verifies against the worker's shared key.
///
/// Refuses (returns `Err`) when:
/// - the envelope is missing required fields;
/// - the signature is empty (production subscribers must NOT accept
///   unsigned envelopes);
/// - the actor_id is malformed;
/// - the HMAC fails;
/// - the subject doesn't match.
///
/// Pure function so the verification rule can be unit-tested without
/// NATS / a live worker.
#[allow(dead_code)] // Provided for future subscribers; tests exercise it.
pub fn verify_signed_agent_envelope(
    expected_subject: &str,
    envelope_bytes: &[u8],
) -> Result<serde_json::Value, &'static str> {
    let parsed: serde_json::Value =
        serde_json::from_slice(envelope_bytes).map_err(|_| "envelope parse failed")?;
    let envelope = parsed.as_object().ok_or("envelope is not a JSON object")?;

    let signature_hex = envelope
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or("envelope missing signature field")?;
    if signature_hex.is_empty() {
        return Err("envelope has empty signature — refusing");
    }
    let signature = hex::decode(signature_hex).map_err(|_| "signature is not valid hex")?;

    let subject = envelope
        .get("subject")
        .and_then(|v| v.as_str())
        .ok_or("envelope missing subject field")?;
    if subject != expected_subject {
        return Err("subject mismatch — possible re-publication attempt");
    }
    let nonce = envelope
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or("envelope missing nonce field")?;
    let actor_str = envelope
        .get("source_actor")
        .and_then(|v| v.as_str())
        .ok_or("envelope missing source_actor field")?;
    let actor_id = uuid::Uuid::parse_str(actor_str).map_err(|_| "source_actor is not a UUID")?;

    // Reconstruct the canonical body (envelope MINUS signature) and
    // verify. This mirrors `build_signed_agent_envelope`'s canonical
    // form exactly.
    let mut body_obj = envelope.clone();
    body_obj.remove("signature");
    let canonical_body = serde_json::to_vec(&serde_json::Value::Object(body_obj))
        .map_err(|_| "canonical body serialise failed")?;

    if !talos_memory::rpc_auth::verify(subject, actor_id, nonce, &canonical_body, &signature) {
        return Err("signature verification failed");
    }

    envelope
        .get("payload")
        .cloned()
        .ok_or("envelope missing payload field")
}

impl wit_agent_orchestration::Host for TalosContext {
    async fn invoke(
        &mut self,
        msg: wit_agent_orchestration::AgentMessage,
        timeout_ms: u32,
    ) -> Result<wit_agent_orchestration::AgentResponse, wit_agent_orchestration::Error> {
        // Defense-in-depth: only Trusted world should use agent orchestration.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Agent | CapabilityWorld::Trusted
        ) {
            // MCP-697 (2026-05-13): audit-ledger parity (sibling of MCP-696).
            // Agent orchestration is a high-blast-radius surface (NATS
            // RPC + cross-agent message passing); a Minimal-world probe
            // of `invoke` should leave a WORM trail. The `target` is
            // caller-supplied; record it raw (already length+charset
            // validated 14 lines below) so the audit ledger captures
            // *which* agent the malicious module tried to talk to.
            self.record_capability_denied("agent-invoke", "capability-world", &msg.target)
                .await;
            tracing::warn!(module_id = ?self.module_id, "WASM module attempted agent invoke but lacks Agent or Trusted capability");
            return Err(wit_agent_orchestration::Error::PermissionDenied);
        }

        let nats = self
            .nats_client
            .as_ref()
            .ok_or(wit_agent_orchestration::Error::InvocationFailed)?;

        // Cap timeout to 120 seconds (WIT spec maximum)
        let timeout = std::time::Duration::from_millis(timeout_ms.min(120_000) as u64);

        // SECURITY: Sanitize agent target name to prevent NATS topic injection.
        // Only allow alphanumeric, hyphens, and underscores in topic segments.
        if msg.target.is_empty()
            || msg.target.len() > 128
            || !msg
                .target
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            tracing::warn!(
                target = %msg.target,
                module_id = ?self.module_id,
                "Invalid agent target name — must be 1-128 alphanumeric/hyphen/underscore characters"
            );
            return Err(wit_agent_orchestration::Error::AgentNotFound);
        }

        // H-4: per-field caps to bound the NATS envelope size. The host
        // stamps source_module / source_execution / nonce / signature
        // itself; the only guest-controlled blobs are `payload`, `target`
        // (length+charset checked above), and `correlation_id` (an
        // `option<string>` in the WIT, capped below).
        if msg.payload.len() > MAX_AGENT_PAYLOAD_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                payload_bytes = msg.payload.len(),
                cap = MAX_AGENT_PAYLOAD_BYTES,
                "agent payload exceeds cap"
            );
            return Err(wit_agent_orchestration::Error::InvocationFailed);
        }
        if correlation_id_exceeds_cap(&msg.correlation_id) {
            // Log length only — an oversized attacker-controlled blob must
            // not itself be blasted into the logs.
            tracing::warn!(
                module_id = ?self.module_id,
                correlation_id_bytes = msg.correlation_id.as_ref().map(|c| c.len()).unwrap_or(0),
                cap = MAX_AGENT_CORRELATION_ID_BYTES,
                "agent correlation_id exceeds cap"
            );
            return Err(wit_agent_orchestration::Error::InvocationFailed);
        }

        // Build NATS topic for agent invocation
        let topic = talos_workflow_job_protocol::subjects::agent_invoke_for(&msg.target);

        // H-4: build a SIGNED envelope. Pre-fix the payload was an
        // unsigned JSON object on `talos.agent.*` — any in-cluster
        // attacker (or a future regression that lifts the topic outside
        // the worker's authentication boundary) could publish arbitrary
        // bytes that subscribers might trust. The envelope now carries
        // an HMAC-SHA256 signature bound to subject + actor_id + nonce
        // + canonical body, plus replay-protection nonce. Subscribers
        // under `talos.agent.*` MUST verify before acting on the
        // contents.
        let payload_json: serde_json::Value = serde_json::from_str(&msg.payload)
            .unwrap_or_else(|_| serde_json::Value::String(msg.payload.clone()));
        let payload_bytes = build_signed_agent_envelope(
            &topic,
            self.actor_id,
            crate::worker_identity::worker_identity(),
            &self.module_id,
            &self.execution_id,
            &payload_json,
            &msg.correlation_id,
        )
        .map_err(|err| {
            tracing::warn!(
                module_id = ?self.module_id,
                err = %err,
                "Failed to build signed agent envelope"
            );
            wit_agent_orchestration::Error::InvocationFailed
        })?;

        // NATS request-reply with timeout
        let response = tokio::time::timeout(timeout, nats.request(topic, payload_bytes.into()))
            .await
            .map_err(|_| {
                tracing::warn!(target_agent = %msg.target, "Agent invocation timed out");
                wit_agent_orchestration::Error::Timeout
            })?
            .map_err(|e| {
                tracing::warn!(target_agent = %msg.target, error = %e, "Agent invocation failed");
                wit_agent_orchestration::Error::InvocationFailed
            })?;

        // Parse response
        let resp: serde_json::Value = serde_json::from_slice(&response.payload)
            .map_err(|_| wit_agent_orchestration::Error::InvocationFailed)?;

        Ok(wit_agent_orchestration::AgentResponse {
            source: msg.target,
            payload: resp
                .get("payload")
                .and_then(|v| v.as_str())
                .unwrap_or("{}")
                .to_string(),
            success: resp
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            correlation_id: msg.correlation_id,
        })
    }

    async fn inject_runtime_node(
        &mut self,
        _module_id: String,
        _config: String,
    ) -> Result<String, wit_agent_orchestration::Error> {
        // To be implemented in Phase 3 (Signal to Controller).
        // SECURITY: When implemented, MUST validate that the injected node's
        // capability world does not exceed the calling actor's max_world ceiling.
        // Use get_actor_max_world() and CapabilityWorld::is_subset_of() to enforce.
        // Without this check, a Trusted-world module could inject arbitrary capability
        // nodes, bypassing actor-level governance restrictions.
        Err(wit_agent_orchestration::Error::InvocationFailed)
    }

    async fn reroute_to_node(
        &mut self,
        _node_id: String,
    ) -> Result<(), wit_agent_orchestration::Error> {
        // To be implemented in Phase 3 (Signal to Controller).
        // SECURITY: When implemented, MUST verify the target node belongs to the
        // same workflow and the calling module has permission to alter control flow.
        Err(wit_agent_orchestration::Error::InvocationFailed)
    }

    async fn send(
        &mut self,
        msg: wit_agent_orchestration::AgentMessage,
    ) -> Result<(), wit_agent_orchestration::Error> {
        // Defense-in-depth: only Trusted world should use agent orchestration.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Agent | CapabilityWorld::Trusted
        ) {
            // MCP-697 (2026-05-13): audit-ledger parity — see agent::invoke above.
            self.record_capability_denied("agent-send", "capability-world", &msg.target)
                .await;
            tracing::warn!(module_id = ?self.module_id, "WASM module attempted agent send but lacks Agent or Trusted capability");
            return Err(wit_agent_orchestration::Error::PermissionDenied);
        }

        let nats = self
            .nats_client
            .as_ref()
            .ok_or(wit_agent_orchestration::Error::InvocationFailed)?;

        // SECURITY: Sanitize agent target name (same rules as invoke).
        if msg.target.is_empty()
            || msg.target.len() > 128
            || !msg
                .target
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            tracing::warn!(
                target = %msg.target,
                module_id = ?self.module_id,
                "Invalid agent target name for send"
            );
            return Err(wit_agent_orchestration::Error::AgentNotFound);
        }

        // H-4: per-field caps (same as invoke).
        if msg.payload.len() > MAX_AGENT_PAYLOAD_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                payload_bytes = msg.payload.len(),
                cap = MAX_AGENT_PAYLOAD_BYTES,
                "agent send payload exceeds cap"
            );
            return Err(wit_agent_orchestration::Error::InvocationFailed);
        }
        if correlation_id_exceeds_cap(&msg.correlation_id) {
            // Log length only — see invoke() above.
            tracing::warn!(
                module_id = ?self.module_id,
                correlation_id_bytes = msg.correlation_id.as_ref().map(|c| c.len()).unwrap_or(0),
                cap = MAX_AGENT_CORRELATION_ID_BYTES,
                "agent send correlation_id exceeds cap"
            );
            return Err(wit_agent_orchestration::Error::InvocationFailed);
        }

        let topic = talos_workflow_job_protocol::subjects::agent_message_for(&msg.target);

        // H-4: signed NATS envelope, see invoke() above for rationale.
        let payload_json: serde_json::Value = serde_json::from_str(&msg.payload)
            .unwrap_or_else(|_| serde_json::Value::String(msg.payload.clone()));
        let payload_bytes = build_signed_agent_envelope(
            &topic,
            self.actor_id,
            crate::worker_identity::worker_identity(),
            &self.module_id,
            &self.execution_id,
            &payload_json,
            &msg.correlation_id,
        )
        .map_err(|err| {
            tracing::warn!(
                module_id = ?self.module_id,
                err = %err,
                "Failed to build signed agent envelope for send"
            );
            wit_agent_orchestration::Error::InvocationFailed
        })?;

        // Fire-and-forget publish
        nats.publish(topic, payload_bytes.into())
            .await
            .map_err(|e| {
                tracing::warn!(target_agent = %msg.target, error = %e, "Agent message send failed");
                wit_agent_orchestration::Error::InvocationFailed
            })?;

        Ok(())
    }

    async fn list_agents(&mut self) -> Result<Vec<String>, wit_agent_orchestration::Error> {
        // MCP-669 (2026-05-13): per-method capability gate. Siblings
        // `invoke` and `send` both gate on Agent | Trusted; this one
        // didn't. Today the implementation returns an empty list so the
        // gap is harmless — but defense-in-depth is the whole point of
        // the per-method gate rule (MCP-586/601/655). Without the gate,
        // a future implementation that enumerates real agent IDs would
        // silently leak them to any world that imports the interface,
        // including a minimal-world module that obtained accidental
        // linkage via operator override or wit_inspector returning
        // Unknown. Pair this with `invoke`/`send` so all three methods
        // share the same world-eligibility surface.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Agent | CapabilityWorld::Trusted
        ) {
            // MCP-697 (2026-05-13): audit-ledger parity — see agent::invoke above.
            // `list_agents` has no target arg; empty target string is the
            // canonical placeholder (matches the graphql-execute pattern).
            self.record_capability_denied("agent-list", "capability-world", "")
                .await;
            tracing::warn!(module_id = ?self.module_id, "WASM module attempted agent list_agents but lacks Agent or Trusted capability");
            return Err(wit_agent_orchestration::Error::PermissionDenied);
        }
        // Query available agents via NATS subject enumeration.
        // Returns empty list until agent registry is implemented.
        Ok(vec![])
    }
}

#[cfg(test)]
mod correlation_id_cap_tests {
    use super::{correlation_id_exceeds_cap, MAX_AGENT_CORRELATION_ID_BYTES};

    #[test]
    fn none_is_within_cap() {
        assert!(!correlation_id_exceeds_cap(&None));
    }

    #[test]
    fn exactly_at_cap_is_accepted() {
        let cid = "a".repeat(MAX_AGENT_CORRELATION_ID_BYTES);
        assert_eq!(cid.len(), MAX_AGENT_CORRELATION_ID_BYTES);
        assert!(!correlation_id_exceeds_cap(&Some(cid)));
    }

    #[test]
    fn one_over_cap_is_rejected() {
        let cid = "a".repeat(MAX_AGENT_CORRELATION_ID_BYTES + 1);
        assert!(correlation_id_exceeds_cap(&Some(cid)));
    }

    #[test]
    fn multibyte_utf8_cap_is_byte_based_not_char_based() {
        // 'é' is 2 bytes in UTF-8. 129 of them = 258 bytes > 256-byte cap
        // even though the CHAR count (129) is well under the cap. The cap
        // bounds envelope bytes, so this must be rejected — and because we
        // reject rather than truncate, there is no fixed-byte-offset slice
        // that could panic on a codepoint boundary.
        let cid = "é".repeat(129);
        assert_eq!(cid.len(), 258);
        assert!(correlation_id_exceeds_cap(&Some(cid)));

        // 128 × 'é' = 256 bytes = exactly at cap → accepted.
        let cid = "é".repeat(128);
        assert_eq!(cid.len(), MAX_AGENT_CORRELATION_ID_BYTES);
        assert!(!correlation_id_exceeds_cap(&Some(cid)));
    }
}

#[cfg(test)]
mod signed_agent_envelope_tests {
    use super::{build_signed_agent_envelope, verify_signed_agent_envelope};
    use talos_memory::rpc_auth;

    /// Register a process-wide HMAC key for the verify tests. Reuses the
    /// same all-`0x42` test key convention as the protocol crate. Safe
    /// to call from multiple tests — `register_hmac_key` is idempotent
    /// for the same key bytes.
    fn ensure_test_key() {
        use std::sync::Arc;
        rpc_auth::register_hmac_key(Arc::new(vec![0x42u8; 32]));
    }

    #[test]
    fn signed_envelope_round_trips() {
        ensure_test_key();
        let subject = "talos.agent.alice.invoke";
        let actor = uuid::Uuid::nil();
        let payload = serde_json::json!({"task": "do thing"});
        let bytes = build_signed_agent_envelope(
            subject,
            Some(actor),
            "worker-1",
            &Some("mod-1".to_string()),
            &Some("exec-1".to_string()),
            &payload,
            &Some("corr-1".to_string()),
        )
        .expect("build envelope");

        let verified = verify_signed_agent_envelope(subject, &bytes).expect("verify must succeed");
        assert_eq!(verified, payload);
    }

    #[test]
    fn empty_signature_is_refused() {
        // Future subscribers MUST NOT trust an unsigned envelope. We
        // simulate the "HMAC key not registered" path by constructing
        // an envelope with an empty signature field directly.
        let envelope = serde_json::json!({
            "v": 1,
            "nonce": "0:00000000000000000000000000000000",
            "subject": "talos.agent.alice.invoke",
            "source_module": "mod-1",
            "source_execution": "exec-1",
            "source_actor": uuid::Uuid::nil().to_string(),
            "source_worker": "worker-1",
            "payload": {"task": "do thing"},
            "correlation_id": null,
            "signature": "",
        });
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let res = verify_signed_agent_envelope("talos.agent.alice.invoke", &bytes);
        assert!(res.is_err(), "empty signature must be refused");
    }

    #[test]
    fn subject_mismatch_is_refused() {
        ensure_test_key();
        let bytes = build_signed_agent_envelope(
            "talos.agent.alice.invoke",
            Some(uuid::Uuid::nil()),
            "worker-1",
            &None,
            &None,
            &serde_json::json!({}),
            &None,
        )
        .expect("build envelope");
        // Subscriber on a DIFFERENT topic should refuse — defense
        // against an attacker who re-publishes a captured envelope on
        // an unrelated subject.
        let res = verify_signed_agent_envelope("talos.agent.eve.invoke", &bytes);
        assert!(res.is_err(), "subject mismatch must be refused");
    }

    #[test]
    fn tampered_payload_is_refused() {
        ensure_test_key();
        let subject = "talos.agent.alice.invoke";
        let bytes = build_signed_agent_envelope(
            subject,
            Some(uuid::Uuid::nil()),
            "worker-1",
            &None,
            &None,
            &serde_json::json!({"task": "original"}),
            &None,
        )
        .expect("build envelope");

        // Parse, tamper the payload, re-serialise WITHOUT re-signing.
        let mut envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        envelope["payload"] = serde_json::json!({"task": "tampered"});
        let tampered_bytes = serde_json::to_vec(&envelope).unwrap();

        let res = verify_signed_agent_envelope(subject, &tampered_bytes);
        assert!(res.is_err(), "tampered payload must fail HMAC verify");
    }
}
