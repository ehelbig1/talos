//! `secrets` host interface (handle-based access, tier-2 expose gate).

use super::*;

// ============================================================================
// Secrets
// ============================================================================

/// Maximum Tier-2 expose-secret calls per execution (prevent bulk extraction).
const MAX_EXPOSE_CALLS_PER_EXECUTION: u64 = 10;

// MCP-673 (2026-05-13): per-method capability gate helper for wit_secrets.
// Mirrors the gate already present in `get_secret`; lifted into a helper
// so the four follow-on methods (release_slot / hmac_sign / expose_secret /
// resolve_config_vault) can adopt it without copy-pasting the matches!.
// Sibling pattern to MCP-602 (require_object_storage_capability),
// MCP-603 (require_state_capability), MCP-608/609 (per-method inline
// gates on agent_memory / llm_tools), MCP-655 (governance::request_approval),
// MCP-669 (agent_orchestration::list_agents). resolve_config_vault is
// transitively gated through get_secret; the other three are not, so
// even though `release_slot(arbitrary_u64)` is operationally harmless,
// `hmac_sign` and `expose_secret` operate on secret material and must
// not be reachable from a Minimal/Unknown-world module that obtained
// accidental linkage. Defense-in-depth: don't rely on `get_secret`'s
// gate to indirectly protect handles a future bug might hand out.
fn require_secrets_capability(
    world: &crate::wit_inspector::CapabilityWorld,
) -> Result<(), wit_secrets::Error> {
    use crate::wit_inspector::CapabilityWorld;
    if matches!(
        world,
        CapabilityWorld::Secrets
            | CapabilityWorld::Database
            | CapabilityWorld::Agent
            | CapabilityWorld::Trusted
    ) {
        Ok(())
    } else {
        tracing::warn!(
            ?world,
            "WASM module attempted wit_secrets call but lacks Secrets/Database/Agent/Trusted capability"
        );
        Err(wit_secrets::Error::Unauthorized)
    }
}

impl wit_secrets::Host for TalosContext {
    /// Tier 0 — Resolve a vault path to an opaque slot handle (u64).
    ///
    /// The plaintext value is materialized inside the host's DashMap; the guest
    /// receives only the u64 handle.  Slot persists until `release-slot` or
    /// execution end — use it with Tier-1 ops or Tier-2 `expose-secret`.
    async fn get_secret(&mut self, key_path: String) -> Result<u64, wit_secrets::Error> {
        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __result: Result<u64, wit_secrets::Error> = async move {
        // MCP-588: per-execution rate limit. Pre-fix this path was the
        // only audited host function without a per-execution cap — a
        // module could loop get_secret thousands of times in tight
        // succession, flooding `talos.audit.ledger` with NATS publishes
        // and burning controller-side audit-consumer CPU. Same pattern
        // as MCP-523 (wit_email) / MCP-537 (wit_webhook + wit_graphql).
        if !self.check_rate_limit(
            &self.secret_access_count,
            MAX_SECRET_ACCESSES_PER_EXECUTION,
        ) {
            tracing::warn!(
                module_id = ?self.module_id,
                "secrets::get_secret rate limit exceeded"
            );
            if let Some(ref m) = self.metrics {
                m.record_rate_limit_exceeded("secrets");
            }
            return Err(wit_secrets::Error::Unauthorized);
        }
        // Normalize: strip vault:// prefix so both "vault://my/key" and "my/key"
        // resolve identically. This makes get_secret safe to call directly with
        // raw config field values that may carry the prefix notation.
        let key_path = key_path
            .strip_prefix("vault://")
            .map(str::to_string)
            .unwrap_or(key_path);

        use crate::wit_inspector::CapabilityWorld;
        // Capability gate. The agent-node world (`Agent`) explicitly imports
        // the `secrets` interface in talos.wit, so its modules MUST be able
        // to call get_secret at runtime. Earlier this list omitted `Agent`,
        // which made every agent-node module's get_secret call return
        // `Unauthorized` regardless of allowed_secrets / actor grants /
        // namespace — surfacing as a confusing dead-end during real-workflow
        // building (see the pa-ship-report investigation, 2026-04-22).
        // The other secret-tier worlds (Secrets, Database, Trusted) are
        // already in the list because their WIT worlds also import secrets.
        if !matches!(
            self.capability_world,
            CapabilityWorld::Secrets
                | CapabilityWorld::Database
                | CapabilityWorld::Agent
                | CapabilityWorld::Trusted
        ) {
            // Hash before audit — same convention as the secret-allowlist
            // deny below; operators reading the ledger should not learn
            // unowned vault paths from a capability-world deny either.
            let key_hash = format!("{:x}", Sha256::digest(key_path.as_bytes()));
            self.record_capability_denied("secret-access", "capability-world", &key_hash)
                .await;
            tracing::warn!(
                gate = "capability_world",
                module_id = ?self.module_id,
                capability_world = ?self.capability_world,
                key_path,
                "WASM module attempted secrets access but capability world does not import the secrets interface. \
                 Recompile with capability_world: secrets-node (or higher: agent-node, database-node, automation-node)."
            );
            return Err(wit_secrets::Error::Unauthorized);
        }

        // SECURITY: per-module secret allowlist. Enforced via shared helper so
        // guest-initiated (get_secret) and host-initiated (resolve_vault_header)
        // paths stay in lockstep. Returning Unauthorized (not Notfound) lets
        // operators distinguish access-control failures from missing paths; the
        // path is never confirmed to exist.
        if self.check_secret_allowlist(&key_path).is_err() {
            // Audit the DENIED attempt with the key-path SHA-256 (never the
            // key_path itself — operators reading the ledger should not learn
            // unowned vault paths). Pairs with the host-reserved deny-list
            // catch (LLM provider keys) which lives inside check_secret_allowlist.
            let key_hash = format!("{:x}", Sha256::digest(key_path.as_bytes()));
            self.record_capability_denied("secret-access", "secret-allowlist", &key_hash)
                .await;
            return Err(wit_secrets::Error::Unauthorized);
        }

        if let Some(ledger_mutex) = &self.audit_ledger {
            let key_hash = format!("{:x}", Sha256::digest(key_path.as_bytes()));
            let mut ledger = ledger_mutex.lock().await;
            let event = ledger.append(
                "agent:wasm",
                "wasi:secrets_get",
                &serde_json::json!({ "key_hash": key_hash }).to_string(),
            );
            drop(ledger);

            if let Some(n) = &self.nats_client {
                let event_clone = event.clone();
                let nats = n.clone();
                tokio::spawn(async move {
                    let payload = serde_json::json!({
                        "event": event_clone.clone(),
                        "hash": event_clone.calculate_hash()
                    });
                    match serde_json::to_vec(&payload) {
                        Ok(bytes) => {
                            // MCP-735: log NATS publish failure so SIEM
                            // consumers see the gap. Local ledger.append
                            // above is the WORM source-of-truth; this
                            // publish is replication only.
                            if let Err(e) = nats
                                .publish(talos_workflow_job_protocol::subjects::AUDIT_LEDGER.to_string(), bytes.into())
                                .await
                            {
                                tracing::warn!(
                                    target: "talos_rpc",
                                    error = %e,
                                    "audit-ledger NATS replication failed (secrets_get) — local ledger unaffected, SIEM stream will miss this event"
                                );
                            }
                        }
                        Err(e) => tracing::error!(
                            "Failed to serialize audit event for secrets_get: {}",
                            e
                        ),
                    }
                });
            }
        }

        // Resolve via the SecretProvider — materializes the secret in the host DashMap.
        // The u64 handle is all that crosses the WASM boundary; plaintext stays host-side.
        let exec_id = self
            .execution_id
            .as_deref()
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
            .unwrap_or_else(uuid::Uuid::new_v4);

        match self.provider.resolve(&key_path, exec_id).await {
            Ok(handle) => Ok(handle.0), // return the raw u64; slot stays alive for Tier-1/2 use
            Err(_) => {
                tracing::warn!(
                    key_path,
                    module_id = ?self.module_id,
                    "WASM module requested a secret that is not available"
                );
                Err(wit_secrets::Error::Notfound)
            }
        }
        }.await;

        if let Some(ref m) = __metrics {
            m.record_host_function_call(
                "secrets::get_secret",
                __start.elapsed().as_millis() as f64,
            );
        }
        __result
    }

    /// Release a slot early — zeroes host-side memory immediately.
    async fn release_slot(&mut self, handle: u64) -> Result<(), wit_secrets::Error> {
        // MCP-673: defense-in-depth gate. release_slot is operationally
        // harmless against random u64 handles (provider returns Ok), but
        // adopting the gate keeps every wit_secrets method consistent so
        // a future contributor copy-pasting from any sibling lands on
        // the right shape.
        // MCP-713 (2026-05-13): audit-ledger parity. Pre-fix the `?`
        // operator on `require_secrets_capability` propagated Err
        // without an audit row — operator-blind to the WORM ledger.
        // Same fix shape as MCP-712 wit_state sweep.
        if require_secrets_capability(&self.capability_world).is_err() {
            self.record_capability_denied(
                "secrets-release-slot",
                "capability-world",
                &handle.to_string(),
            )
            .await;
            return Err(wit_secrets::Error::Unauthorized);
        }
        let _ = self
            .provider
            .release(talos_secrets::SlotHandle(handle))
            .await;
        Ok(())
    }

    /// Tier 1 — HMAC-SHA256-sign `data` using the key in the slot.
    /// Secret bytes never cross the WASM boundary; only the 32-byte signature is returned.
    async fn hmac_sign(
        &mut self,
        handle: u64,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, wit_secrets::Error> {
        // MCP-673: per-method capability gate. hmac_sign produces a
        // signature DERIVED from secret material; a Minimal-world
        // module that obtained a valid handle through accidental
        // linkage would otherwise be able to sign-as-the-secret without
        // the secret ever crossing the WIT boundary. Fail closed before
        // touching the provider.
        // MCP-713 (2026-05-13): audit-ledger parity. A capability-deny
        // on hmac_sign is a high-signal event — the module tried to
        // sign WITH a secret it couldn't legally access via a handle
        // it shouldn't have been able to obtain. That MUST be in the
        // audit ledger loudly, not just `tracing::warn!`-only via the
        // helper's internal warn.
        if require_secrets_capability(&self.capability_world).is_err() {
            self.record_capability_denied(
                "secrets-hmac-sign",
                "capability-world",
                &handle.to_string(),
            )
            .await;
            return Err(wit_secrets::Error::Unauthorized);
        }
        self.provider
            .sign(talos_secrets::SlotHandle(handle), &data)
            .map_err(|e| {
                let err_msg = e.to_string();
                tracing::warn!(handle, error = %err_msg, module_id = ?self.module_id, "hmac-sign failed");
                // Map to contextual error: stale/expired slots vs invalid handles
                if err_msg.contains("expired") || err_msg.contains("stale") || err_msg.contains("age") {
                    wit_secrets::Error::Expired
                } else {
                    wit_secrets::Error::Notfound
                }
            })
    }

    /// Tier 2 — Explicit, audited plaintext exposure crossing the WASM boundary.
    ///
    /// Every call is logged at WARN, rate-limited to MAX_EXPOSE_CALLS_PER_EXECUTION
    /// per execution and MAX_TIER2_EXPOSES_PER_USER_PER_DAY globally per user,
    /// and sets the execution trace flag `secret_tier2_exposed`.
    async fn expose_secret(
        &mut self,
        handle: u64,
        reason: String,
    ) -> Result<String, wit_secrets::Error> {
        // Wasm-security review 2026-05-23: the audit-row `reason` field is
        // operator-supplied free text that flows verbatim into the WORM
        // ledger AND NATS audit stream. The WIT-side handle bounds the
        // call but does NOT bound the string length: a guest with
        // `allow_tier2_exposure: true` and the per-execution call budget
        // (MAX_EXPOSE_CALLS_PER_EXECUTION = 10) could send 100 MB strings
        // 10× per execution — a gigabyte of audit data per call site, with
        // the same NATS subscriber fanout multiplying the storage cost
        // downstream. 1 KiB matches the operator-recognised pattern of
        // "free text long enough for forensic context, short enough that
        // no caller has a legitimate reason to need more." Truncate at
        // char boundary so the redacted form doesn't split a UTF-8
        // sequence and break downstream JSON parsing.
        const MAX_EXPOSE_REASON_BYTES: usize = 1024;
        let reason = if reason.len() > MAX_EXPOSE_REASON_BYTES {
            let mut s =
                talos_text_util::truncate_at_char_boundary(&reason, MAX_EXPOSE_REASON_BYTES)
                    .to_string();
            s.push_str("...[TRUNCATED]");
            s
        } else {
            reason
        };
        // MCP-673: per-method capability gate. expose_secret is the
        // single grep-able Tier-2 plaintext exit point (line below),
        // so the per-method gate is highest-stakes here. The existing
        // `allow_tier2_exposure` policy gate is necessary but not
        // sufficient — a module's `allow_tier2_exposure: true` plus a
        // hypothetical Minimal-world linkage bug would expose plaintext
        // without the world ceiling that compile-time linkage normally
        // enforces. Defense-in-depth: refuse before any rate-limit
        // counter increments or audit log entries.
        // MCP-713 (2026-05-13): audit-ledger parity. expose_secret is
        // the HIGHEST-VALUE audit target in wit_secrets — a
        // capability-deny here means a module attempted to cross the
        // Tier-2 plaintext exit boundary without the right world.
        // Pre-fix the `?` propagated silently; only `tracing::warn!`
        // evidence remained. The post-fix audit row fires BEFORE the
        // policy / rate-limit / WARN cascade below, so dashboards
        // alerting on `record_capability_denied` light up immediately.
        if require_secrets_capability(&self.capability_world).is_err() {
            self.record_capability_denied(
                "secrets-expose-secret",
                "capability-world",
                &handle.to_string(),
            )
            .await;
            return Err(wit_secrets::Error::Unauthorized);
        }
        // Policy gate: block Tier-2 exposure unless the module explicitly
        // opted in via `allow_tier2_exposure: true` in its metadata. The
        // vast majority of modules only need Tier-1 (vault:// header
        // resolution or slot-based fetch_with_header). Blocking by default
        // ensures a module cannot exfiltrate secrets into WASM guest memory
        // without the platform operator's explicit consent.
        if !self.allow_tier2_exposure {
            tracing::warn!(
                handle,
                module_id = ?self.module_id,
                reason = %reason,
                "expose_secret blocked: module does not have allow_tier2_exposure enabled. \
                 Use Tier-1 (vault:// headers or fetch_with_header) instead, or set \
                 allow_tier2_exposure=true on the module if plaintext access is required."
            );
            return Err(wit_secrets::Error::Unauthorized);
        }

        // Rate-limit: prevent bulk extraction via repeated expose-secret calls.
        let count = self
            .expose_call_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count >= MAX_EXPOSE_CALLS_PER_EXECUTION {
            tracing::warn!(
                handle,
                count,
                module_id = ?self.module_id,
                "expose-secret rate limit exceeded ({} calls/execution max)",
                MAX_EXPOSE_CALLS_PER_EXECUTION
            );
            return Err(wit_secrets::Error::Ratelimited);
        }

        // Global rate limit: per-user daily limit across all executions (Redis-backed).
        if let Some(user_id) = self.user_id {
            let today_utc = chrono::Utc::now();
            let today_naive = today_utc.date_naive();
            let today = today_utc.format("%Y-%m-%d").to_string();
            let key = format!("talos:tier2_expose:{}:{}", user_id, today);

            // M-2 (2026-05-22): replaces the prior process-wide
            // `Arc<AtomicU64>` fallback with a per-user
            // `(date, counter)` map. Pre-fix one tenant exhausting the
            // counter denied service to every other tenant on the
            // worker pod until restart. The new shape isolates
            // tenants AND self-rotates at the day boundary. Both the
            // Redis-error and Redis-absent paths route through the
            // same fallback helper — keeping MCP-722's "never-configured
            // = same fail-closed path as outage" invariant intact.
            use crate::expose_fallback::FallbackVerdict;
            let global_allowed = if let Some(ref redis) = self.redis_client {
                match Self::check_global_expose_limit(redis, &key).await {
                    Ok(allowed) => allowed,
                    Err(e) => {
                        let verdict = self.global_expose_fallback.check_and_increment(
                            user_id,
                            today_naive,
                            MAX_TIER2_EXPOSES_PER_USER_PER_DAY,
                        );
                        let (allowed, fallback_count) = match verdict {
                            FallbackVerdict::Allowed { count } => (true, count),
                            FallbackVerdict::Denied { count } => (false, count),
                        };
                        tracing::warn!(
                            user_id = %user_id,
                            error = %e,
                            fallback_count,
                            "Redis global expose limit check failed, using in-memory fallback ({}/{})",
                            fallback_count,
                            MAX_TIER2_EXPOSES_PER_USER_PER_DAY
                        );
                        allowed
                    }
                }
            } else {
                // MCP-722 (2026-05-13): Redis ABSENT (env-unconfigured)
                // must follow the same fallback path as Redis-ERROR.
                // Pre-fix this arm returned `true` unconditionally,
                // silently bypassing the daily per-user cap whenever
                // an operator ran the worker without Redis configured.
                // M-2 (2026-05-22): the fallback is now per-user, not
                // process-wide — see expose_fallback.rs.
                let verdict = self.global_expose_fallback.check_and_increment(
                    user_id,
                    today_naive,
                    MAX_TIER2_EXPOSES_PER_USER_PER_DAY,
                );
                let (allowed, fallback_count) = match verdict {
                    FallbackVerdict::Allowed { count } => (true, count),
                    FallbackVerdict::Denied { count } => (false, count),
                };
                tracing::warn!(
                    user_id = %user_id,
                    fallback_count,
                    "Redis not configured for global expose limit; using in-memory fallback ({}/{})",
                    fallback_count,
                    MAX_TIER2_EXPOSES_PER_USER_PER_DAY
                );
                allowed
            };

            if !global_allowed {
                tracing::warn!(
                    user_id = %user_id,
                    limit = MAX_TIER2_EXPOSES_PER_USER_PER_DAY,
                    "Global Tier-2 secret exposure limit exceeded (daily limit)"
                );
                return Err(wit_secrets::Error::Ratelimited);
            }
        }

        // Mark execution trace — this execution performed an explicit Tier-2 exposure.
        self.secret_tier2_exposed
            .store(true, std::sync::atomic::Ordering::Relaxed);

        // Mandatory audit log — visible in structured logs and NATS audit stream.
        tracing::warn!(
            handle,
            reason = %reason,
            module_id = ?self.module_id,
            execution_id = ?self.execution_id,
            user_id = ?self.user_id,
            "TIER-2 secret exposure: plaintext crossing WASM boundary (expose-secret)"
        );

        // MCP-723 (2026-05-13): doc-drift closure. The comment above says
        // "NATS audit stream" but pre-fix only `tracing::warn!` fired —
        // local-log only, no WORM ledger row, no NATS replication. For
        // the HIGHEST-VALUE audit target (Tier-2 plaintext exposure)
        // this was a real omission; operators relying on the NATS
        // audit stream for SIEM ingestion would never see expose_secret
        // events. Sibling `get_secret` line ~2483 already follows this
        // shape — append to the local ledger, then fire-and-forget
        // publish to `talos.audit.ledger`. The reason string is
        // caller-supplied free text; it goes through the audit pipe
        // verbatim because operators rely on it for forensic context
        // ("why did this module expose secret X"). Length is bounded by
        // the WIT-side handle (no host cap today; future hardening
        // could clamp at e.g. 1 KiB).
        if let Some(ledger_mutex) = &self.audit_ledger {
            let mut ledger = ledger_mutex.lock().await;
            let event = ledger.append(
                "agent:wasm",
                "wasi:secrets_expose",
                &serde_json::json!({
                    "handle": handle,
                    "reason": &reason,
                    "module_id": self.module_id.as_ref().map(|u| u.to_string()),
                    "execution_id": self.execution_id.clone(),
                    "user_id": self.user_id.map(|u| u.to_string()),
                })
                .to_string(),
            );
            drop(ledger);
            if let Some(n) = &self.nats_client {
                let event_clone = event.clone();
                let nats = n.clone();
                tokio::spawn(async move {
                    let payload = serde_json::json!({
                        "event": event_clone.clone(),
                        "hash": event_clone.calculate_hash()
                    });
                    match serde_json::to_vec(&payload) {
                        Ok(bytes) => {
                            // MCP-735: HIGHEST-stakes audit replication.
                            // expose_secret is the single grep-able
                            // Tier-2 plaintext exit point — losing the
                            // SIEM signal silently means a plaintext-
                            // exposure event is invisible to the
                            // operator's alerting layer. Local ledger
                            // still has the event, but the WARN here is
                            // the only operational signal that
                            // replication failed.
                            if let Err(e) = nats
                                .publish(
                                    talos_workflow_job_protocol::subjects::AUDIT_LEDGER.to_string(),
                                    bytes.into(),
                                )
                                .await
                            {
                                tracing::warn!(
                                    target: "talos_rpc",
                                    error = %e,
                                    "audit-ledger NATS replication failed (secrets_expose) — local ledger unaffected, SIEM stream will miss a Tier-2 plaintext-exposure event"
                                );
                            }
                        }
                        Err(e) => tracing::error!(
                            "Failed to serialize audit event for secrets_expose: {}",
                            e
                        ),
                    }
                });
            }
        }

        // expose_slot is the single grep-able Tier-2 plaintext exit point.
        // L-4: provider returns Zeroizing<String>; we unwrap into an
        // owned String (the WIT return type requires String) at the
        // immediate point of use. The Zeroizing wrapper drops + wipes
        // when its scope ends. The returned String crosses the WASM
        // boundary into guest memory — Tier-2 by design, audited above.
        //
        // Wasm-security review 2026-05-23 (L-finding-2): the plaintext
        // String returned here lives in WASM linear memory for the
        // remainder of the execution. The host's `Zeroizing<String>`
        // drops + wipes its own copy at end-of-scope, but the WIT ABI's
        // String return semantically MOVES bytes into the guest's
        // wasm32 address space — the host cannot reach back and zero
        // them. The guest is responsible for narrowing the lifetime
        // (drop after use, overwrite with zeros, or `talos_sdk`'s
        // `ScopedSecret` helper which scrubs on Drop). At
        // execution-end the entire wasmtime `Store` is destroyed and
        // its linear-memory backing region is dropped by the host
        // allocator — but heap pages may sit in physical memory until
        // overwritten by a subsequent allocation, so a coincident host
        // memory dump still risks recovery. Operators who can't accept
        // that residency window MUST leave `allow_tier2_exposure`
        // false and use Tier-1 (`vault://` header substitution or
        // `fetch_with_header`), which never lands plaintext in guest
        // memory at all. The per-module `allow_tier2_exposure` flag
        // (gated above) IS the operator's acknowledgement of this
        // residency window — keep it false unless a specific module
        // documents why plaintext must cross the boundary.
        self.provider
            .into_auth_header(talos_secrets::SlotHandle(handle), "expose-secret")
            .map(|wrapped| (*wrapped).clone())
            .map_err(|e| {
                tracing::warn!(handle, error = %e, "expose-secret slot lookup failed");
                wit_secrets::Error::Notfound
            })
    }

    /// Tier-1 resolution for config fields that may contain `vault://` references.
    ///
    /// Strips the `vault://` prefix if present, then delegates to `get_secret`
    /// for the same allowlist check, audit logging, and provider resolution.
    /// The returned u64 is an opaque slot handle — no plaintext reaches guest memory.
    async fn resolve_config_vault(
        &mut self,
        config_value: String,
    ) -> Result<u64, wit_secrets::Error> {
        // This function is specifically for resolving vault:// config values.
        // Reject inputs without the prefix to prevent misuse as a get_secret alias.
        let path = match config_value.strip_prefix("vault://") {
            Some(p) => p.to_string(),
            None => {
                tracing::warn!(
                    config_value,
                    module_id = ?self.module_id,
                    "resolve_config_vault called without vault:// prefix"
                );
                return Err(wit_secrets::Error::Notfound);
            }
        };
        self.get_secret(path).await
    }
}
