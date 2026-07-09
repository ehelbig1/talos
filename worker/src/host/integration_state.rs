//! `integration-state` (per-integration scoped persistent kv store)
//! host interface (signed NATS-RPC to the controller).

use super::*;

// ============================================================================
// Integration State (per-integration scoped persistent kv store)
// ============================================================================
//
// Backed by NATS-RPC to the controller. integration_name comes from the
// module's compiled-in metadata via TalosContext.integration_name —
// guest code has no way to forge it. Modules without an integration_name
// (the vast majority) get Unauthorized from every call without ANY
// network round-trip, so calling these from an inappropriate module is
// cheap to fail.

// MCP-606 (2026-05-12): per-method capability gate for integration-state.
// WIT-world linkage restricts `talos:core/integration-state` to
// `agent-node` and `automation-node` (verified via grep `import
// integration-state` in wit/talos.wit) — both map to
// `CapabilityWorld::Agent` / `Trusted`. Pre-fix none of the four
// methods (set / get / delete / list_entries) checked the runtime
// world. The integration-state RPC is the durability path for OAuth
// tokens, push-notification watches, and other privileged
// integration metadata; a mis-tagged module that linked could
// read/write/enumerate those entries. Same shape as MCP-602/603/604.
fn require_integration_state_capability(
    world: &crate::wit_inspector::CapabilityWorld,
) -> Result<(), wit_integration_state::Error> {
    use crate::wit_inspector::CapabilityWorld;
    if matches!(world, CapabilityWorld::Agent | CapabilityWorld::Trusted) {
        Ok(())
    } else {
        tracing::warn!(
            ?world,
            "WASM module attempted wit_integration_state call but lacks Agent/Trusted capability"
        );
        Err(wit_integration_state::Error::NotAvailable)
    }
}

impl wit_integration_state::Host for TalosContext {
    async fn set(
        &mut self,
        entry: wit_integration_state::StoredEntry,
    ) -> Result<(), wit_integration_state::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity (sibling of MCP-696).
        // integration-state is the durability path for OAuth tokens +
        // push-notification watches — Minimal/Secrets-world probes of
        // this surface MUST leave a WORM trail. Inline pattern matches
        // wit_object_storage / wit_llm_streaming (helper is sync; audit
        // happens at the call site before delegating).
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Agent
                | crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            self.record_capability_denied(
                "wit_integration_state::set",
                "capability-world",
                &entry.key,
            )
            .await;
        }
        require_integration_state_capability(&self.capability_world)?;
        // Write-ceiling gate: integration-state is the durable write path
        // for OAuth tokens + watch state — refuse for read-only actors.
        // Inert unless enforcement is on.
        if self
            .write_ceiling_refuses("integration-state-set", &entry.key)
            .await
        {
            return Err(wit_integration_state::Error::Unauthorized);
        }
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        // Bail before the NATS round-trip if the execution was cancelled
        // (outer timeout, explicit abort). Matches the pattern in
        // http::fetch and the other hosts — a cancelled execution
        // shouldn't be able to extend its blast radius by kicking off
        // new RPCs.
        if self.is_cancelled() {
            return Err(wit_integration_state::Error::NotAvailable);
        }
        // Pull owned prereqs SYNCHRONOUSLY before any await — holding
        // &mut self across an await point pulls in WASI's non-Send
        // resource handles via TalosContext, which the bindgen requires
        // to be Send. The agent_memory impls solve this the same way
        // (mem_rpc_prereqs_owned + free call_memory_op).
        let prereqs = self.integration_state_ctx_owned();
        let __res = integration_state_set_owned(prereqs, entry).await;
        if let Some(ref m) = __metrics {
            m.record_host_function_call(
                "integration_state::set",
                __start.elapsed().as_millis() as f64,
            );
        }
        __res
    }

    async fn get(
        &mut self,
        key: String,
    ) -> Result<wit_integration_state::StoredEntry, wit_integration_state::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity — see integration_state::set above.
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Agent
                | crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            self.record_capability_denied("wit_integration_state::get", "capability-world", &key)
                .await;
        }
        require_integration_state_capability(&self.capability_world)?;
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        if self.is_cancelled() {
            return Err(wit_integration_state::Error::NotAvailable);
        }
        let prereqs = self.integration_state_ctx_owned();
        let __res = integration_state_get_owned(prereqs, key).await;
        if let Some(ref m) = __metrics {
            m.record_host_function_call(
                "integration_state::get",
                __start.elapsed().as_millis() as f64,
            );
        }
        __res
    }

    async fn delete(&mut self, key: String) -> Result<(), wit_integration_state::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity — see integration_state::set above.
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Agent
                | crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            self.record_capability_denied(
                "wit_integration_state::delete",
                "capability-world",
                &key,
            )
            .await;
        }
        require_integration_state_capability(&self.capability_world)?;
        // Write-ceiling gate: read-only actors cannot delete integration
        // state. Inert unless enforcement is on.
        if self
            .write_ceiling_refuses("integration-state-delete", &key)
            .await
        {
            return Err(wit_integration_state::Error::Unauthorized);
        }
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        if self.is_cancelled() {
            return Err(wit_integration_state::Error::NotAvailable);
        }
        let prereqs = self.integration_state_ctx_owned();
        let __res = integration_state_delete_owned(prereqs, key).await;
        if let Some(ref m) = __metrics {
            m.record_host_function_call(
                "integration_state::delete",
                __start.elapsed().as_millis() as f64,
            );
        }
        __res
    }

    async fn list_entries(
        &mut self,
        filter: wit_integration_state::ListFilter,
    ) -> Result<Vec<wit_integration_state::StoredEntry>, wit_integration_state::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity — see integration_state::set above.
        // filter has no single canonical target; empty target encodes the
        // enumerate-shaped probe.
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Agent
                | crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            let _ = &filter;
            self.record_capability_denied(
                "wit_integration_state::list_entries",
                "capability-world",
                "",
            )
            .await;
        }
        require_integration_state_capability(&self.capability_world)?;
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        if self.is_cancelled() {
            return Err(wit_integration_state::Error::NotAvailable);
        }
        let prereqs = self.integration_state_ctx_owned();
        let __res = integration_state_list_owned(prereqs, filter).await;
        if let Some(ref m) = __metrics {
            m.record_host_function_call(
                "integration_state::list",
                __start.elapsed().as_millis() as f64,
            );
        }
        __res
    }
}

// Free async helpers — own their captures, so no `&mut self` lifetime
// extends across an await boundary.

type IntegrationPrereqs = Result<
    (
        String,
        uuid::Uuid,
        uuid::Uuid,
        std::sync::Arc<async_nats::Client>,
    ),
    wit_integration_state::Error,
>;

async fn integration_state_set_owned(
    prereqs: IntegrationPrereqs,
    entry: wit_integration_state::StoredEntry,
) -> Result<(), wit_integration_state::Error> {
    use talos_memory::integration_state_rpc::{
        IndexedSlots, IntegrationOp, IntegrationStateReply, IntegrationStateRequest,
        REQUEST_TIMEOUT_MS, SUBJECT_INTEGRATION_STATE_OP,
    };
    let (integration_name, actor_id, user_id, nats) = prereqs?;
    let value: serde_json::Value = serde_json::from_str(&entry.value)
        .map_err(|_| wit_integration_state::Error::InvalidInput)?;
    let op = IntegrationOp::Set {
        key: entry.key,
        value,
        ttl_seconds: entry.ttl_seconds,
        slots: IndexedSlots {
            idx_str_1: entry.idx_str_one,
            idx_str_2: entry.idx_str_two,
            idx_ts_1_ms: entry.idx_ts_one_ms,
            idx_int_1: entry.idx_int_one,
        },
    };
    let req = IntegrationStateRequest::new_signed(integration_name, actor_id, user_id, op)
        .ok_or(wit_integration_state::Error::InvalidInput)?;
    let reply: IntegrationStateReply =
        send_integration_request(&nats, req, SUBJECT_INTEGRATION_STATE_OP, REQUEST_TIMEOUT_MS)
            .await?;
    match reply.result {
        Ok(_) => Ok(()),
        Err(e) => Err(map_integration_err(e)),
    }
}

async fn integration_state_get_owned(
    prereqs: IntegrationPrereqs,
    key: String,
) -> Result<wit_integration_state::StoredEntry, wit_integration_state::Error> {
    use talos_memory::integration_state_rpc::{
        IntegrationOp, IntegrationOpResult, IntegrationStateReply, IntegrationStateRequest,
        REQUEST_TIMEOUT_MS, SUBJECT_INTEGRATION_STATE_OP,
    };
    let (integration_name, actor_id, user_id, nats) = prereqs?;
    let op = IntegrationOp::Get { key };
    let req = IntegrationStateRequest::new_signed(integration_name, actor_id, user_id, op)
        .ok_or(wit_integration_state::Error::InvalidInput)?;
    let reply: IntegrationStateReply =
        send_integration_request(&nats, req, SUBJECT_INTEGRATION_STATE_OP, REQUEST_TIMEOUT_MS)
            .await?;
    match reply.result {
        Ok(IntegrationOpResult::Entry { entry }) => Ok(stored_to_wit(entry)),
        Ok(_) => Err(wit_integration_state::Error::InvalidInput),
        Err(e) => Err(map_integration_err(e)),
    }
}

async fn integration_state_delete_owned(
    prereqs: IntegrationPrereqs,
    key: String,
) -> Result<(), wit_integration_state::Error> {
    use talos_memory::integration_state_rpc::{
        IntegrationOp, IntegrationStateReply, IntegrationStateRequest, REQUEST_TIMEOUT_MS,
        SUBJECT_INTEGRATION_STATE_OP,
    };
    let (integration_name, actor_id, user_id, nats) = prereqs?;
    let op = IntegrationOp::Delete { key };
    let req = IntegrationStateRequest::new_signed(integration_name, actor_id, user_id, op)
        .ok_or(wit_integration_state::Error::InvalidInput)?;
    let reply: IntegrationStateReply =
        send_integration_request(&nats, req, SUBJECT_INTEGRATION_STATE_OP, REQUEST_TIMEOUT_MS)
            .await?;
    match reply.result {
        Ok(_) => Ok(()),
        Err(e) => Err(map_integration_err(e)),
    }
}

async fn integration_state_list_owned(
    prereqs: IntegrationPrereqs,
    filter: wit_integration_state::ListFilter,
) -> Result<Vec<wit_integration_state::StoredEntry>, wit_integration_state::Error> {
    use talos_memory::integration_state_rpc::{
        IntegrationOp, IntegrationOpResult, IntegrationStateReply, IntegrationStateRequest,
        ListFilter as RpcFilter, MAX_RESULT_LIMIT, REQUEST_TIMEOUT_MS,
        SUBJECT_INTEGRATION_STATE_OP,
    };
    let (integration_name, actor_id, user_id, nats) = prereqs?;
    let limit = filter.limit.clamp(1, MAX_RESULT_LIMIT);
    let op = IntegrationOp::List {
        filter: RpcFilter {
            key_prefix: filter.key_prefix,
            idx_str_1_eq: filter.idx_str_one_eq,
            idx_str_2_eq: filter.idx_str_two_eq,
            idx_ts_1_gte_ms: filter.idx_ts_one_gte_ms,
            idx_ts_1_lt_ms: filter.idx_ts_one_lt_ms,
            idx_int_1_eq: filter.idx_int_one_eq,
        },
        limit,
    };
    let req = IntegrationStateRequest::new_signed(integration_name, actor_id, user_id, op)
        .ok_or(wit_integration_state::Error::InvalidInput)?;
    let reply: IntegrationStateReply =
        send_integration_request(&nats, req, SUBJECT_INTEGRATION_STATE_OP, REQUEST_TIMEOUT_MS)
            .await?;
    match reply.result {
        Ok(IntegrationOpResult::Entries { entries }) => {
            Ok(entries.into_iter().map(stored_to_wit).collect())
        }
        Ok(_) => Err(wit_integration_state::Error::InvalidInput),
        Err(e) => Err(map_integration_err(e)),
    }
}

impl TalosContext {
    /// Owned snapshot of the prereqs needed for every integration_state
    /// RPC. Returning owned values lets the four host fns kick off async
    /// work without holding `&self` across an await — important because
    /// TalosContext contains WASI's non-Send resource handles, so any
    /// `&mut self` that survived an await would fail bindgen's Send bounds.
    fn integration_state_ctx_owned(&self) -> IntegrationPrereqs {
        let integration_name = match self.integration_name.as_ref() {
            Some(n) if !n.is_empty() => n.clone(),
            _ => return Err(wit_integration_state::Error::Unauthorized),
        };
        let actor_id = self
            .actor_id
            .ok_or(wit_integration_state::Error::NotAvailable)?;
        let user_id = self
            .user_id
            .ok_or(wit_integration_state::Error::NotAvailable)?;
        let nats = self
            .nats_client
            .as_ref()
            .cloned()
            .ok_or(wit_integration_state::Error::NotAvailable)?;
        Ok((integration_name, actor_id, user_id, nats))
    }
}

async fn send_integration_request(
    nats: &async_nats::Client,
    req: talos_memory::integration_state_rpc::IntegrationStateRequest,
    subject: &str,
    timeout_ms: u64,
) -> Result<talos_memory::integration_state_rpc::IntegrationStateReply, wit_integration_state::Error>
{
    let payload = match serde_json::to_vec(&req) {
        Ok(p) => p,
        Err(_) => return Err(wit_integration_state::Error::InvalidInput),
    };
    let fut = nats.request(subject.to_string(), payload.into());
    let reply_msg =
        match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), fut).await {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "integration_state NATS request failed");
                return Err(wit_integration_state::Error::NotAvailable);
            }
            Err(_) => return Err(wit_integration_state::Error::Timeout),
        };
    serde_json::from_slice(&reply_msg.payload)
        .map_err(|_| wit_integration_state::Error::InvalidInput)
}

fn stored_to_wit(
    e: talos_memory::integration_state_rpc::StoredEntry,
) -> wit_integration_state::StoredEntry {
    // WIT contract: `ttl_seconds` on reads means "remaining lifetime in
    // seconds" (not the original TTL the row was set with). Compute from
    // the stored expires_at_ms + current time. A negative remaining value
    // would indicate a row returned despite being expired (shouldn't
    // happen — the controller query filters on `expires_at > now()` —
    // but clamp at 0 defensively so guests never see a negative count).
    let ttl_seconds = e.expires_at_ms.and_then(|exp_ms| {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis() as i64;
        let remaining_ms = exp_ms.saturating_sub(now_ms).max(0);
        Some((remaining_ms / 1000) as u64)
    });
    wit_integration_state::StoredEntry {
        key: e.key,
        value: e.value,
        ttl_seconds,
        idx_str_one: e.slots.idx_str_1,
        idx_str_two: e.slots.idx_str_2,
        idx_ts_one_ms: e.slots.idx_ts_1_ms,
        idx_int_one: e.slots.idx_int_1,
    }
}

fn map_integration_err(
    e: talos_memory::integration_state_rpc::IntegrationStateError,
) -> wit_integration_state::Error {
    use talos_memory::integration_state_rpc::IntegrationStateError as E;
    match e {
        E::NotAvailable => wit_integration_state::Error::NotAvailable,
        E::KeyNotFound => wit_integration_state::Error::NotFound,
        E::InvalidInput(_) => wit_integration_state::Error::InvalidInput,
        E::Unauthorized => wit_integration_state::Error::Unauthorized,
        E::StorageFull => wit_integration_state::Error::StorageFull,
        E::Timeout => wit_integration_state::Error::Timeout,
        E::Internal(_) => wit_integration_state::Error::NotAvailable,
    }
}

#[cfg(test)]
mod integration_state_helper_tests {
    use super::*;
    use talos_memory::integration_state_rpc::{IndexedSlots, IntegrationStateError, StoredEntry};

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    #[test]
    fn stored_to_wit_no_expiry_has_none_ttl() {
        let e = StoredEntry {
            key: "k".into(),
            value: "\"v\"".into(),
            updated_at_ms: 0,
            expires_at_ms: None,
            slots: IndexedSlots::default(),
        };
        let wit = stored_to_wit(e);
        assert!(wit.ttl_seconds.is_none());
    }

    #[test]
    fn stored_to_wit_future_expiry_has_positive_remaining() {
        let e = StoredEntry {
            key: "k".into(),
            value: "\"v\"".into(),
            updated_at_ms: 0,
            expires_at_ms: Some(now_ms() + 60_000), // 60s ahead
            slots: IndexedSlots::default(),
        };
        let wit = stored_to_wit(e);
        let ttl = wit.ttl_seconds.expect("ttl must be Some for future expiry");
        assert!(
            ttl > 0 && ttl <= 60,
            "remaining must be in (0, 60]: {}",
            ttl
        );
    }

    #[test]
    fn stored_to_wit_past_expiry_clamps_to_zero() {
        let e = StoredEntry {
            key: "k".into(),
            value: "\"v\"".into(),
            updated_at_ms: 0,
            expires_at_ms: Some(now_ms() - 60_000),
            slots: IndexedSlots::default(),
        };
        let wit = stored_to_wit(e);
        assert_eq!(
            wit.ttl_seconds,
            Some(0),
            "expired row must clamp to 0, never negative"
        );
    }

    #[test]
    fn stored_to_wit_slot_name_mapping() {
        // RPC uses snake_case `idx_str_1`; WIT uses `idx_str_one` because
        // WIT identifier segments can't start with digits. Lock the
        // cross-naming contract so a rename on either side is caught.
        let e = StoredEntry {
            key: "k".into(),
            value: "{}".into(),
            updated_at_ms: 0,
            expires_at_ms: None,
            slots: IndexedSlots {
                idx_str_1: Some("a".into()),
                idx_str_2: Some("b".into()),
                idx_ts_1_ms: Some(123),
                idx_int_1: Some(456),
            },
        };
        let wit = stored_to_wit(e);
        assert_eq!(wit.idx_str_one.as_deref(), Some("a"));
        assert_eq!(wit.idx_str_two.as_deref(), Some("b"));
        assert_eq!(wit.idx_ts_one_ms, Some(123));
        assert_eq!(wit.idx_int_one, Some(456));
    }

    #[test]
    fn map_integration_err_internal_becomes_not_available() {
        // Lossy on purpose: Internal carries raw DB text that MUST NOT
        // reach guest code. Collapsing to NotAvailable drops the detail
        // at the trust boundary.
        let mapped = map_integration_err(IntegrationStateError::Internal(
            "CONSTRAINT violation foo_bar_baz_chk".into(),
        ));
        assert!(matches!(mapped, wit_integration_state::Error::NotAvailable));
    }

    #[test]
    fn map_integration_err_key_not_found_becomes_not_found() {
        let mapped = map_integration_err(IntegrationStateError::KeyNotFound);
        assert!(matches!(mapped, wit_integration_state::Error::NotFound));
    }

    #[test]
    fn map_integration_err_invalid_input_drops_detail() {
        let mapped = map_integration_err(IntegrationStateError::InvalidInput(
            "leaky internal detail".into(),
        ));
        assert!(matches!(mapped, wit_integration_state::Error::InvalidInput));
    }

    #[test]
    fn map_integration_err_all_variants_covered() {
        use IntegrationStateError as E;
        let cases = [
            (E::NotAvailable, wit_integration_state::Error::NotAvailable),
            (E::KeyNotFound, wit_integration_state::Error::NotFound),
            (E::Unauthorized, wit_integration_state::Error::Unauthorized),
            (E::StorageFull, wit_integration_state::Error::StorageFull),
            (E::Timeout, wit_integration_state::Error::Timeout),
        ];
        for (src, expected) in cases {
            let got = map_integration_err(src);
            assert_eq!(
                std::mem::discriminant(&got),
                std::mem::discriminant(&expected)
            );
        }
    }
}
