#[cfg(test)]
mod tests {
    use crate::audit::{AuditEvent, ExecutionLedger};

    #[test]
    fn test_audit_event_calculate_hash_deterministic() {
        let event = AuditEvent {
            workflow_id: "wf-123".to_string(),
            execution_id: "exec-456".to_string(),
            sequence_num: 1,
            timestamp: 1234567890,
            actor: "agent:test".to_string(),
            action: "test:action".to_string(),
            payload: r#"{"key":"value"}"#.to_string(),
            previous_hash: "genesis".to_string(),
            hmac_signature: None,
        };

        let hash1 = event.calculate_hash();
        let hash2 = event.calculate_hash();

        // Hash should be deterministic
        assert_eq!(hash1, hash2);
        // Hash should be 64 hex characters (SHA-256)
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_audit_event_hash_changes_with_field() {
        let event1 = AuditEvent {
            workflow_id: "wf-123".to_string(),
            execution_id: "exec-456".to_string(),
            sequence_num: 1,
            timestamp: 1234567890,
            actor: "agent:test".to_string(),
            action: "test:action".to_string(),
            payload: r#"{"key":"value"}"#.to_string(),
            previous_hash: "genesis".to_string(),
            hmac_signature: None,
        };

        let event2 = AuditEvent {
            workflow_id: "wf-123".to_string(),
            execution_id: "exec-456".to_string(),
            sequence_num: 2, // Different sequence
            timestamp: 1234567890,
            actor: "agent:test".to_string(),
            action: "test:action".to_string(),
            payload: r#"{"key":"value"}"#.to_string(),
            previous_hash: "genesis".to_string(),
            hmac_signature: None,
        };

        assert_ne!(event1.calculate_hash(), event2.calculate_hash());
    }

    #[test]
    fn test_audit_event_colon_in_payload_not_confused() {
        // This test verifies that colons in payload don't break the hash
        let event1 = AuditEvent {
            workflow_id: "wf-123".to_string(),
            execution_id: "exec-456".to_string(),
            sequence_num: 1,
            timestamp: 1234567890,
            actor: "agent:test".to_string(),
            action: "test:action".to_string(),
            payload: "a:b".to_string(),
            previous_hash: "genesis".to_string(),
            hmac_signature: None,
        };

        let event2 = AuditEvent {
            workflow_id: "wf-123".to_string(),
            execution_id: "exec-456".to_string(),
            sequence_num: 1,
            timestamp: 1234567890,
            actor: "agent:test".to_string(),
            action: "test:action".to_string(),
            payload: "ab".to_string(), // Different payload, no colon
            previous_hash: "genesis".to_string(),
            hmac_signature: None,
        };

        // These should produce different hashes
        assert_ne!(event1.calculate_hash(), event2.calculate_hash());
    }

    #[test]
    fn test_execution_ledger_genesis() {
        let ledger = ExecutionLedger::new("wf-123", "exec-456");

        assert_eq!(ledger.workflow_id, "wf-123");
        assert_eq!(ledger.execution_id, "exec-456");
        assert_eq!(ledger.current_sequence, 0);
        assert!(!ledger.last_hash.is_empty());
        assert_eq!(ledger.last_hash.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_execution_ledger_append_increments_sequence() {
        let mut ledger = ExecutionLedger::new("wf-123", "exec-456");

        let event1 = ledger.append("agent:test", "action:1", "payload1");
        assert_eq!(event1.sequence_num, 1);

        let event2 = ledger.append("agent:test", "action:2", "payload2");
        assert_eq!(event2.sequence_num, 2);

        assert_eq!(ledger.current_sequence, 2);
    }

    #[test]
    fn test_execution_ledger_chain_integrity() {
        let mut ledger = ExecutionLedger::new("wf-123", "exec-456");
        let genesis_hash = ledger.last_hash.clone();

        let event1 = ledger.append("agent:test", "action:1", "payload1");
        // First event's previous_hash should be the genesis hash
        assert_eq!(event1.previous_hash, genesis_hash);
        // Ledger's last_hash should now be event1's hash
        assert_eq!(ledger.last_hash, event1.calculate_hash());

        let event2 = ledger.append("agent:test", "action:2", "payload2");
        // Second event's previous_hash should be event1's hash
        assert_eq!(event2.previous_hash, event1.calculate_hash());
        // Ledger's last_hash should now be event2's hash
        assert_eq!(ledger.last_hash, event2.calculate_hash());
    }

    #[test]
    fn test_execution_ledger_different_executions_different_genesis() {
        let ledger1 = ExecutionLedger::new("wf-123", "exec-456");
        let ledger2 = ExecutionLedger::new("wf-123", "exec-789");
        let ledger3 = ExecutionLedger::new("wf-abc", "exec-456");

        // Different executions should have different genesis hashes
        assert_ne!(ledger1.last_hash, ledger2.last_hash);
        assert_ne!(ledger1.last_hash, ledger3.last_hash);
        assert_ne!(ledger2.last_hash, ledger3.last_hash);
    }

    /// MCP-490: pre-fix the genesis hash was
    /// `SHA-256("genesis:" + workflow_id + "|" + execution_id)`. With
    /// pipes inside either id, two distinct tuples collided. Length
    /// prefixes fix this — same encoding discipline as
    /// `AuditEvent::calculate_hash`. UUIDs don't contain pipes today,
    /// so this is defense-in-depth, not a live exploit.
    #[test]
    fn test_genesis_hash_resists_pipe_delimiter_injection() {
        let a = ExecutionLedger::new("wf|x", "ec1");
        let b = ExecutionLedger::new("wf", "x|ec1");
        assert_ne!(
            a.last_hash, b.last_hash,
            "pipe in id must not collide genesis hash"
        );
    }

    #[test]
    fn test_genesis_hash_resists_empty_id_collision() {
        // Edge case: empty workflow_id with executed_id = pipe-prefixed,
        // versus standard layout. The length prefix discriminates.
        let a = ExecutionLedger::new("", "ec1");
        let b = ExecutionLedger::new("ec1", "");
        assert_ne!(a.last_hash, b.last_hash);
    }

    #[test]
    fn test_audit_event_populates_all_fields() {
        let mut ledger = ExecutionLedger::new("wf-123", "exec-456");
        let event = ledger.append("agent:test", "action:test", r#"{"data":123}"#);

        assert_eq!(event.workflow_id, "wf-123");
        assert_eq!(event.execution_id, "exec-456");
        assert_eq!(event.actor, "agent:test");
        assert_eq!(event.action, "action:test");
        assert_eq!(event.payload, r#"{"data":123}"#);
        assert!(!event.previous_hash.is_empty());
        // Timestamp should be set (within last minute since test started)
        assert!(event.timestamp > 0);
    }

    /// Verifies the on-the-wire shape of a capability_denied event matches
    /// what `TalosContext::record_capability_denied` produces. The action
    /// string and payload schema are the public contract for downstream
    /// consumers (operator dashboards, SIEM filters, the WORM subscriber's
    /// OTLP span attributes) — changing them here means changing the
    /// dashboards too.
    #[test]
    fn test_capability_denied_event_shape() {
        let mut ledger = ExecutionLedger::new("wf-x", "exec-y");
        // Mirror exactly what record_capability_denied builds — a JSON
        // string with the canonical capability/policy/target/actor_id/
        // module_id keys.
        let payload = serde_json::json!({
            "capability": "http-fetch",
            "policy": "tier1-llm-egress",
            "target": "api.anthropic.com",
            "actor_id": "00000000-0000-0000-0000-000000000001",
            "module_id": "mod-abc",
        })
        .to_string();
        let event = ledger.append("worker", "wasi:capability_denied", &payload);

        assert_eq!(event.actor, "worker");
        assert_eq!(event.action, "wasi:capability_denied");
        // Payload must be valid JSON with the expected keys.
        let parsed: serde_json::Value =
            serde_json::from_str(&event.payload).expect("payload is valid JSON");
        assert_eq!(parsed["capability"], "http-fetch");
        assert_eq!(parsed["policy"], "tier1-llm-egress");
        assert_eq!(parsed["target"], "api.anthropic.com");
        assert_eq!(parsed["actor_id"], "00000000-0000-0000-0000-000000000001");
        assert_eq!(parsed["module_id"], "mod-abc");
    }

    /// Capability denials must integrate cleanly with secret-access events
    /// in the same execution chain — the hash-chain links must not break
    /// because of action-string differences. This guards against a future
    /// refactor that changes the chain hash to depend on the action enum.
    #[test]
    fn test_capability_denied_chains_with_other_events() {
        let mut ledger = ExecutionLedger::new("wf-mixed", "exec-mixed");
        let secret_payload = r#"{"key_hash":"abc"}"#;
        let denied_payload =
            r#"{"capability":"secret-access","policy":"secret-allowlist","target":"deadbeef"}"#;

        let secret_event = ledger.append("agent:wasm", "wasi:secrets_get", secret_payload);
        let denied_event = ledger.append("worker", "wasi:capability_denied", denied_payload);
        let next_event = ledger.append("agent:wasm", "wasi:secrets_get", secret_payload);

        // Sequence numbers must be monotonic across mixed event types.
        assert_eq!(secret_event.sequence_num, 1);
        assert_eq!(denied_event.sequence_num, 2);
        assert_eq!(next_event.sequence_num, 3);
        // Each event's previous_hash must be the prior event's hash —
        // the denial is not a chain-break.
        assert_eq!(denied_event.previous_hash, secret_event.calculate_hash());
        assert_eq!(next_event.previous_hash, denied_event.calculate_hash());
    }

    /// Denial events with semantically distinct payloads must produce
    /// distinct hashes — same chain position, same action, different
    /// (capability, policy, target) tuple should not collide. This is
    /// what gives the audit trail its forensic value.
    #[test]
    fn test_capability_denied_distinct_payloads_distinct_hashes() {
        let mut ledger_a = ExecutionLedger::new("wf-a", "exec-a");
        let mut ledger_b = ExecutionLedger::new("wf-a", "exec-a");

        let event_a = ledger_a.append(
            "worker",
            "wasi:capability_denied",
            r#"{"capability":"http-fetch","policy":"allowed-hosts","target":"evil.com"}"#,
        );
        let event_b = ledger_b.append(
            "worker",
            "wasi:capability_denied",
            r#"{"capability":"http-fetch","policy":"allowed-hosts","target":"different-evil.com"}"#,
        );
        // Same chain position, same actor, same action — only target
        // differs in payload. Hashes MUST differ.
        assert_ne!(event_a.calculate_hash(), event_b.calculate_hash());
    }
}
