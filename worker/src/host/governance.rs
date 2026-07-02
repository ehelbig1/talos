//! `governance` (approval / budget) and `resource-quotas` host
//! interfaces.

use super::*;

// NOTE: In wasmtime ≥43 the outgoing_handler::Host trait is implemented on
// WasiHttpCtxView (projected via WasiHttpView::http()) rather than on the
// user's context type directly.  The default implementation delegates to
// WasiHttpHooks::send_request.  See context.rs WasiHttpView impl for the
// hooks configuration.  Talos nodes should use talos:core/http for
// controlled HTTP with host allowlists and SSRF protection.

use crate::bindings::talos::core::governance;
impl governance::Host for TalosContext {
    async fn request_approval(&mut self, reason: String) -> bool {
        // MCP-655: per-method capability gate. Sibling of the
        // wit_messaging / wit_cache / wit_files inline checks that
        // MCP-586/601 made canonical for tier-3 sub-world Hosts.
        // Governance is a tier-3 sub-world that escalates only to
        // Agent or Trusted (`is_subset_of`: Governance ⊆ Agent | Trusted);
        // any other world reaching this code path means the WIT inspector
        // mis-classified the module, the world rank was bypassed at
        // create_workflow / load time, or a future capability path drifted.
        // Defense in depth — refuse with a `false` return (the WIT
        // signature has no error variant) and log the world for forensics.
        // Returning `false` is operationally indistinguishable from a
        // denial decision so the guest's branch logic still works.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Governance | CapabilityWorld::Agent | CapabilityWorld::Trusted
        ) {
            tracing::warn!(
                world = ?self.capability_world,
                module_id = ?self.module_id,
                "WASM module attempted governance::request_approval but lacks the Governance/Agent/Trusted capability — denying"
            );
            self.record_capability_denied(
                "governance",
                "capability-world-mismatch",
                "request_approval",
            )
            .await;
            return false;
        }

        if let Some(ledger_mutex) = &self.audit_ledger {
            let mut ledger = ledger_mutex.lock().await;
            let event = ledger.append(
                "agent:wasm",
                "wasi:human_approval_request",
                &serde_json::json!({
                    "reason": reason
                })
                .to_string(),
            );
            // Optionally, publish the event to a WORM NATS stream
            if let Some(n) = &self.nats_client {
                let payload = serde_json::json!({
                    "event": event.clone(),
                    "hash": event.calculate_hash()
                });
                // MCP-879 (2026-05-14): same SIEM-replication WARN as
                // the secrets_get sibling (MCP-735) and the
                // database_query sibling above. The local
                // ledger.append remains the WORM source-of-truth.
                if let Err(e) = n
                    .publish(
                        "talos.audit.ledger".to_string(),
                        serde_json::to_vec(&payload).unwrap_or_default().into(),
                    )
                    .await
                {
                    tracing::warn!(
                        target: "talos_rpc",
                        error = %e,
                        "audit-ledger NATS replication failed (human_approval_request) — local ledger unaffected, SIEM stream will miss this event"
                    );
                }
            }
        }

        let exec_id = self
            .execution_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        let workflow_id = self
            .workflow_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        // Record approval request metric (MCP-492: aggregate-only —
        // per-workflow visibility now lives in the audit-event chain,
        // not the Prometheus label space).
        if let Some(ref m) = self.metrics {
            m.record_approval_requested();
        }

        let nats = match &self.nats_client {
            Some(n) => n,
            None => {
                tracing::error!(
                    execution_id = ?self.execution_id,
                    module_id = ?self.module_id,
                    "NATS client not available for governance approvals — returning false \
                     (indistinguishable from denial due to WIT bool return type)"
                );
                return false;
            }
        };

        let redis = match &self.redis_client {
            Some(r) => r,
            None => {
                tracing::error!(
                    execution_id = ?self.execution_id,
                    module_id = ?self.module_id,
                    "Redis client not available for governance approvals — returning false \
                     (indistinguishable from denial due to WIT bool return type)"
                );
                return false;
            }
        };

        let reply_topic = format!("talos.approvals.wait.{}", exec_id);

        // 1. Subscribe to the reply topic FIRST so we don't miss the message
        let mut subscriber = match nats.subscribe(reply_topic.clone()).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to subscribe to NATS topic {}: {}", reply_topic, e);
                return false;
            }
        };

        // 2. Write to Redis
        let mut con = match redis.get_multiplexed_tokio_connection().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to get Redis connection: {}", e);
                return false;
            }
        };

        // The frontend UI is sending the overall `workflow_execution_id` to the API webhook,
        // not the node-specific `exec_id`.
        let redis_key = format!("approval:{}", workflow_id);
        // MCP-739 (2026-05-13): log SET failures. Pre-fix the
        // `let _: redis::RedisResult<()>` discarded errors entirely.
        // This Redis row is the routing table the webhook handler
        // uses to find the reply_topic when an operator clicks
        // approve/deny — without it the click hits the webhook but
        // the response can't be dispatched back to this awaiting
        // task. The function then sits waiting until its outer
        // timeout (default ~120 s+) before returning false, looking
        // like a denial to the guest. Same operator-visibility class
        // as MCP-733/734/735/736. Note: we continue rather than
        // early-return because the NATS subscribe + publish still
        // happen (the operator might trigger via a different path),
        // but logging at WARN ensures dashboards see the gap.
        if let Err(e) = redis::cmd("SET")
            .arg(&redis_key)
            .arg(&reply_topic)
            .arg("EX")
            .arg(86400) // 24 hours
            .query_async::<()>(&mut con)
            .await
        {
            tracing::warn!(
                target: "talos_rpc",
                execution_id = ?self.execution_id,
                workflow_id,
                error = %e,
                "governance approval: Redis SET for reply_topic routing failed — \
                 webhook clicks may not reach this awaiting task; timing out is the \
                 likely outcome"
            );
        }

        // 3. Publish pending notification
        let payload = serde_json::json!({
            "execution_id": exec_id,
            "reason": reason
        })
        .to_string();

        if let Err(e) = nats
            .publish("talos.approvals.pending".to_string(), payload.into())
            .await
        {
            tracing::error!("Failed to publish pending approval notification: {}", e);
            // Continue anyway, maybe it was logged elsewhere
        }

        tracing::info!(
            "Paused execution {} waiting for approval on {}",
            exec_id,
            reply_topic
        );

        // 4. Await the response with a configurable timeout.
        // Default: 24 hours. Governance-world modules get up to 7 days via the
        // execution-level timeout, but the approval wait itself uses a shorter
        // deadline to avoid silent indefinite hangs.
        // MCP-670 (2026-05-13): `=0`-safe env helper. `TALOS_APPROVAL_TIMEOUT_SECS=0`
        // would fire the timer immediately (`Duration::from_secs(0)`), so every
        // approval request returns Pending → false → silently denied without
        // ever reaching the operator. That's the destructive variant of the
        // `=0` footgun class (MCP-639/642/665/668 family).
        let approval_timeout = std::time::Duration::from_secs(
            talos_config::positive_env_or_default::<u64>("TALOS_APPROVAL_TIMEOUT_SECS", 86400),
        );

        use futures_util::stream::StreamExt;
        let result = tokio::time::timeout(approval_timeout, subscriber.next()).await;

        match result {
            Ok(Some(msg)) => {
                // Delete Redis key (best effort)
                let _: redis::RedisResult<()> = redis::cmd("DEL")
                    .arg(&redis_key)
                    .query_async(&mut con)
                    .await;

                let response_str = String::from_utf8_lossy(&msg.payload);
                let approved = response_str.trim().to_lowercase() == "true";
                tracing::info!("Received approval response for {}: {}", exec_id, approved);

                // Record approval decision metric
                if let Some(ref m) = self.metrics {
                    m.record_approval_decided(if approved { "approved" } else { "denied" });
                }

                if let Some(ledger_mutex) = &self.audit_ledger {
                    let mut ledger = ledger_mutex.lock().await;
                    let event = ledger.append(
                        "human:webhook",
                        "wasi:human_approval_response",
                        &serde_json::json!({
                            "approved": approved
                        })
                        .to_string(),
                    );
                    if let Some(n) = &self.nats_client {
                        // MCP-879 (2026-05-14): same SIEM-replication
                        // WARN as the request sibling above and the
                        // MCP-735 secrets_get site. Local ledger is
                        // the WORM source-of-truth.
                        if let Err(e) = n
                            .publish(
                                "talos.audit.ledger".to_string(),
                                serde_json::to_vec(&event).unwrap_or_default().into(),
                            )
                            .await
                        {
                            tracing::warn!(
                                target: "talos_rpc",
                                error = %e,
                                "audit-ledger NATS replication failed (human_approval_response) — local ledger unaffected, SIEM stream will miss this event"
                            );
                        }
                    }
                }
                approved
            }
            Ok(None) => {
                tracing::error!(
                    execution_id = exec_id,
                    "NATS subscription closed before approval response received"
                );
                false
            }
            Err(_) => {
                tracing::warn!(
                    execution_id = exec_id,
                    timeout_secs = approval_timeout.as_secs(),
                    "Approval request timed out after {:?} — treating as denied",
                    approval_timeout
                );
                // Clean up Redis key on timeout
                let _: redis::RedisResult<()> = redis::cmd("DEL")
                    .arg(&redis_key)
                    .query_async(&mut con)
                    .await;
                false
            }
        }
    }
}

// ============================================================================
// Resource Quotas (budget tracking)
// ============================================================================

// MCP-613 (2026-05-12): the per-execution `quota_usage` HashMap is
// guest-controlled — `record_usage(metric, amount)` calls `entry().or_insert`
// for any guest-supplied name. Pre-fix a guest could grow the map
// unbounded by recording usage against millions of distinct (random)
// metric names, each consuming ~32-100 B (String key + (u64,u64) tuple).
// Fuel doesn't account for host-side allocation, so the cost is paid by
// the worker process. Two caps applied per-method:
//   - MAX_QUOTA_METRIC_NAME_BYTES on each `metric` arg (validated early).
//   - MAX_QUOTA_METRICS_PER_EXECUTION on the map size (record_usage
//     refuses to admit a NEW entry after the cap; existing entries
//     still update).
const MAX_QUOTA_METRIC_NAME_BYTES: usize = 64;
const MAX_QUOTA_METRICS_PER_EXECUTION: usize = 100;

impl wit_resource_quotas::Host for TalosContext {
    async fn check_quota(
        &mut self,
        metric: String,
    ) -> Result<wit_resource_quotas::UsageInfo, wit_resource_quotas::Error> {
        if metric.is_empty() || metric.len() > MAX_QUOTA_METRIC_NAME_BYTES {
            return Err(wit_resource_quotas::Error::MetricNotFound);
        }
        let store = self
            .quota_usage
            .lock()
            .map_err(|_| wit_resource_quotas::Error::NotConfigured)?;
        match store.get(&metric) {
            Some(&(used, limit)) => Ok(wit_resource_quotas::UsageInfo {
                metric,
                used,
                limit,
                remaining: limit.saturating_sub(used),
            }),
            None => Err(wit_resource_quotas::Error::MetricNotFound),
        }
    }

    async fn record_usage(
        &mut self,
        metric: String,
        amount: u64,
    ) -> Result<wit_resource_quotas::UsageInfo, wit_resource_quotas::Error> {
        if metric.is_empty() || metric.len() > MAX_QUOTA_METRIC_NAME_BYTES {
            return Err(wit_resource_quotas::Error::NotConfigured);
        }
        let mut store = self
            .quota_usage
            .lock()
            .map_err(|_| wit_resource_quotas::Error::NotConfigured)?;
        // Refuse new metric admissions once cap is reached. Existing
        // entries still update — bounded by the cap chosen above.
        if !store.contains_key(&metric) && store.len() >= MAX_QUOTA_METRICS_PER_EXECUTION {
            tracing::warn!(
                module_id = ?self.module_id,
                metric = %metric,
                cap = MAX_QUOTA_METRICS_PER_EXECUTION,
                "quota_usage map cap reached — refusing new metric registration"
            );
            return Err(wit_resource_quotas::Error::NotConfigured);
        }
        let entry = store.entry(metric.clone()).or_insert((0, 0));
        // If a limit is set (> 0), enforce it. `saturating_add` on the
        // guest-supplied `amount`: an unchecked `+` panics in debug (poisoning
        // this per-execution Mutex → aborting the run) and silently wraps in
        // release (a wrong self-reported counter) when a guest passes a value
        // near u64::MAX. Saturating to u64::MAX is correct here — it still trips
        // the `> entry.1` limit. Sibling of the MCP-1007/1008 integer-overflow
        // hardening; blast radius is self-only (per-execution quota map).
        if entry.1 > 0 && entry.0.saturating_add(amount) > entry.1 {
            if let Some(ref m) = self.metrics {
                m.record_quota_exceeded(&metric);
            }
            return Err(wit_resource_quotas::Error::QuotaExceeded);
        }
        entry.0 = entry.0.saturating_add(amount);
        Ok(wit_resource_quotas::UsageInfo {
            metric,
            used: entry.0,
            limit: entry.1,
            remaining: entry.1.saturating_sub(entry.0),
        })
    }

    async fn list_quotas(&mut self) -> Vec<wit_resource_quotas::UsageInfo> {
        let store = match self.quota_usage.lock() {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        store
            .iter()
            .map(|(metric, &(used, limit))| wit_resource_quotas::UsageInfo {
                metric: metric.clone(),
                used,
                limit,
                remaining: limit.saturating_sub(used),
            })
            .collect()
    }
}
