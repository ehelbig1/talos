//! Background-task spawn helpers for the controller binary's `main()` —
//! moved VERBATIM out of `controller/src/main.rs` in the 2026-07
//! decomposition. Spawn ORDER within each function is preserved exactly;
//! the ORDER in which `main()` calls these functions is load-bearing and
//! stays in main.rs. Also home to the WASM-log broadcast scrubber
//! (`scrub_wasm_log_for_broadcast`), whose only consumer is the NATS
//! log-subscriber loop below.
use crate::*;

/// Maximum characters of WASM-emitted log content broadcast on the
/// `execution_updates` GraphQL subscription. Mirrors the persistence
/// path's per-row cap (`MAX_MSG_LEN` in
/// `talos_execution_repository::add_workflow_log`); kept in lockstep
/// so the live channel can't carry more than the persisted row.
const MAX_BROADCAST_LOG_CHARS: usize = 8 * 1024;

/// Sanitise a WASM-emitted log message for live broadcast on
/// `execution_updates`. Mirrors the pipeline `add_workflow_log` runs
/// before persisting to `workflow_execution_logs.message`:
///   1. char-count truncate to `MAX_BROADCAST_LOG_CHARS`
///   2. strip control chars except newline/tab/carriage return
///   3. DLP redact (`talos_dlp_provider::redact_str`)
///
/// Extracted as a free function so the discipline is unit-testable
/// (the inline call site is otherwise too deep in the NATS subscriber
/// loop to cover without bringing up a NATS test harness).
/// Same MCP-481 / MCP-1011 class — every operator-visible WASM-log
/// surface needs identical scrubbing.
fn scrub_wasm_log_for_broadcast(message: &str) -> String {
    let truncated: String = if message.chars().count() > MAX_BROADCAST_LOG_CHARS {
        let mut s: String = message.chars().take(MAX_BROADCAST_LOG_CHARS).collect();
        s.push_str("... (truncated)");
        s
    } else {
        message.to_string()
    };
    let sanitized: String = truncated
        .chars()
        .filter(|c| !c.is_control() || matches!(*c, '\n' | '\t' | '\r'))
        .collect();
    // 2026-05-28 audit F3 perf follow-up: per-log-line broadcast is a
    // hot path that runs the DLP scrubber per message × per subscriber.
    // The trait-method `redact_str` allocates a fresh String for every
    // pattern even when nothing matches (~14 patterns × `String::from_owned`
    // per call). Switching to the Cow variant keeps the legitimate-log
    // common case allocation-free.
    talos_dlp_provider::redact_str_cow(&sanitized).into_owned()
}

/// Embedding-provider re-probe loop + crypto-invariant orphan gauges +
/// DB-pool saturation gauges. Extracted verbatim from `main()`; spawn order
/// preserved.
pub(crate) fn spawn_metrics_gauge_tasks(db_pool: sqlx::Pool<sqlx::Postgres>) {
    // Background refresh — every 5 min, re-probe the provider so that
    // operator config rotations (key swap, URL change, tier upgrade) are
    // picked up without a controller restart. The interval is intentionally
    // long: even Voyage's free 3 RPM tier loses just ~6% of capacity to
    // these probes.
    tokio::spawn(async {
        let mut ticker = tokio::time::interval(crate::mcp::search::PROVIDER_PROBE_INTERVAL);
        // First tick fires immediately — skip it so we don't double-probe at boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            crate::mcp::search::refresh_embedding_provider_health().await;
        }
    });

    // Background task: crypto-invariant orphan counts. Runs every 60s
    // and updates three gauges the alerts in
    // deploy/observability/alerts.yaml page on. A value > 0 for any of
    // them means at-rest encrypted data is unrecoverable — the same
    // failure mode that silently bit us on 2026-04-24 before Vault
    // persistence was wired up. See docs/security/operational-runbook.md.
    {
        let pool = db_pool.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            // First tick fires immediately — skip it so startup isn't noisy.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Some(m) = metrics::global() {
                    // actor_memory
                    if let Ok(row) = sqlx::query_scalar::<_, i64>(
                        "SELECT COUNT(*) FROM actor_memory am \
                         WHERE NOT EXISTS ( \
                             SELECT 1 FROM encryption_keys ek WHERE ek.id = am.value_key_id \
                         )",
                    )
                    .fetch_one(&pool)
                    .await
                    {
                        m.actor_memory_orphaned_rows.set(row);
                    }
                    // module_executions (payload_enc_key_id is nullable)
                    if let Ok(row) = sqlx::query_scalar::<_, i64>(
                        "SELECT COUNT(*) FROM module_executions me \
                         WHERE me.payload_enc_key_id IS NOT NULL \
                           AND NOT EXISTS ( \
                             SELECT 1 FROM encryption_keys ek WHERE ek.id = me.payload_enc_key_id \
                         )",
                    )
                    .fetch_one(&pool)
                    .await
                    {
                        m.module_execution_orphaned_rows.set(row);
                    }
                    // workflow_executions
                    if let Ok(row) = sqlx::query_scalar::<_, i64>(
                        "SELECT COUNT(*) FROM workflow_executions we \
                         WHERE we.output_enc_key_id IS NOT NULL \
                           AND NOT EXISTS ( \
                             SELECT 1 FROM encryption_keys ek WHERE ek.id = we.output_enc_key_id \
                         )",
                    )
                    .fetch_one(&pool)
                    .await
                    {
                        m.workflow_execution_orphaned_rows.set(row);
                    }
                }
            }
        });
    }

    // Background task: Postgres connection-pool saturation gauges. Runs
    // every 15s and exports size / idle / in-use / max so the alert
    // `TalosDBPoolSaturated` (deploy/observability/alerts.yaml) can fire
    // before acquisitions start blocking on the 10s acquire timeout.
    // Pool state was previously un-instrumented — a saturated pool
    // surfaced only as climbing request latency with no direct signal.
    // The pool is process-local, so every controller replica samples its
    // own; the sum across replicas must stay below the backend's
    // server-side connection ceiling (see the per-subject RPC semaphore
    // note in docs/architecture/managed-cloud.md).
    {
        let pool = db_pool.clone();
        let max_connections: i64 = std::env::var("DB_MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(30);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                ticker.tick().await;
                if let Some(m) = metrics::global() {
                    // `size()` is total connections (idle + in-use);
                    // `num_idle()` is the currently-available subset.
                    let size = i64::from(pool.size());
                    let idle = i64::try_from(pool.num_idle()).unwrap_or(i64::MAX);
                    m.db_pool_connections.set(size);
                    m.db_pool_idle_connections.set(idle);
                    m.db_pool_in_use_connections.set((size - idle).max(0));
                    m.db_pool_max_connections.set(max_connections);
                }
            }
        });
    }
}

/// OCI registry background sync loop. Extracted verbatim from `main()` —
/// must start AFTER `seed_templates` / `seed_marketplace`.
pub(crate) fn spawn_registry_sync(registry: std::sync::Arc<ModuleRegistry>) {
    // ---------- Start OCI Registry background sync loop ----------
    let sync_registry = registry.clone();
    tokio::spawn(async move {
        registry::sync::start_registry_sync_loop(sync_registry).await;
    });
}

/// LLM-keys/DEK cache sweeps, audit-chain verification sweep, bcrypt-cache
/// revocation sweep, and the modules-table reconciliation sweep. Extracted
/// verbatim from `main()`; spawn order preserved.
pub(crate) fn spawn_maintenance_sweeps(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    secrets_manager: std::sync::Arc<SecretsManager>,
    bg_shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    // ---------- Start LLM-keys cache sweep loop ----------
    //
    // The LLM-keys cache (`SecretsManager::llm_keys_cache`) evicts expired
    // entries lazily on read, which bounds memory for *active* users. A user
    // who makes one request and then goes silent leaves their entry in the
    // cache forever. This task sweeps expired entries on a fixed interval
    // so total cache size stays bounded under long-running multi-tenant
    // load with churning users.
    //
    // Interval defaults to 300s (5 min) and is bounded to [60s, 3600s] so
    // operators can tighten the sweep under high-churn workloads without
    // risk of a runaway tight loop. Emits a structured event per sweep so
    // operators can see how much is being evicted.
    let sweep_sm = secrets_manager.clone();
    let sweep_interval_secs: u64 = std::env::var("LLM_KEYS_SWEEP_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300)
        .clamp(60, 3600);
    let llm_sweep_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = llm_sweep_shutdown;
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(sweep_interval_secs));
        // Burn the immediate first tick so we don't sweep an empty cache at startup.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let evicted = sweep_sm.sweep_expired_llm_keys();
                    if evicted > 0 {
                        tracing::info!(
                            target: "talos_engine",
                            event_kind = "llm_keys_cache_sweep",
                            evicted,
                            interval_secs = sweep_interval_secs,
                            "swept expired LLM-keys cache entries"
                        );
                    }
                    // MCP-1093: piggyback on the same tick to bound the
                    // DEK cache's plaintext-AES-key memory residency.
                    // Same rationale as the LLM-keys sweep — `get_dek`
                    // evicts on read but historical DEK ids never
                    // re-queried after key rotation stay in the heap.
                    let dek_evicted = sweep_sm.sweep_expired_deks();
                    if dek_evicted > 0 {
                        tracing::info!(
                            target: "talos_engine",
                            event_kind = "dek_cache_sweep",
                            evicted = dek_evicted,
                            interval_secs = sweep_interval_secs,
                            "swept expired DEK cache entries"
                        );
                    }
                    // MCP-1133: sweep the single-slot `active_dek_cache`
                    // alongside the secondary cache. The MCP-1093 fix
                    // missed this slot — low-traffic deploys post-key-
                    // rotation leave the old active-DEK plaintext in
                    // the heap until the next active-DEK request.
                    if sweep_sm.sweep_expired_active_dek().await {
                        tracing::info!(
                            target: "talos_engine",
                            event_kind = "active_dek_cache_sweep",
                            interval_secs = sweep_interval_secs,
                            "swept expired active-DEK cache entry"
                        );
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("LLM-keys cache sweep loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });

    // ---------- Memory-rank provenance retention sweep ----------
    //
    // Adaptive per-actor memory ranking — Phase 1. The
    // `execution_memory_context` table accrues one row per packed memory per
    // actor-bound execution when `ENABLE_MEMORY_RANK_PROVENANCE` is on. This
    // task deletes rows older than the retention window so the training
    // substrate stays bounded. Gated on the flag: when provenance is OFF the
    // table is never written, so there is nothing to sweep — we skip spawning
    // the loop entirely (the DELETE would only ever hit an empty table).
    // Interval defaults to 3600s, clamped [300s, 86400s].
    //
    // Dependency warning: provenance is captured ONLY on the smart-context
    // path, so `ENABLE_MEMORY_RANK_PROVENANCE=1` records nothing unless
    // `ENABLE_SMART_MEMORY_CONTEXT=1` is also set. Warn loudly so an operator
    // expecting a training corpus isn't surprised by an empty table.
    if talos_config::memory_rank_provenance_enabled()
        && !talos_config::smart_memory_context_enabled()
    {
        tracing::warn!(
            "ENABLE_MEMORY_RANK_PROVENANCE is on but ENABLE_SMART_MEMORY_CONTEXT is off — \
             provenance records ONLY on the smart-context path, so NO training data will be \
             collected. Enable ENABLE_SMART_MEMORY_CONTEXT to accrue the memory-rank corpus."
        );
    }
    if talos_config::memory_rank_provenance_enabled() {
        let prov_pool = db_pool.clone();
        let prov_shutdown = bg_shutdown_rx.clone();
        let prov_interval_secs: u64 = talos_config::positive_env_or_default(
            "MEMORY_RANK_PROVENANCE_SWEEP_INTERVAL_SECS",
            3600,
        )
        .clamp(300, 86_400);
        tokio::spawn(async move {
            let mut shutdown = prov_shutdown;
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(prov_interval_secs));
            // Burn the immediate first tick so we don't sweep at startup.
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let retention_days = talos_config::memory_rank_provenance_retention_days();
                        match talos_memory::sweep_execution_memory_context(
                            &prov_pool,
                            retention_days,
                        )
                        .await
                        {
                            Ok(n) if n > 0 => tracing::info!(
                                target: "talos_engine",
                                event_kind = "memory_rank_provenance_sweep",
                                deleted = n,
                                retention_days,
                                "swept expired memory-rank provenance rows"
                            ),
                            Ok(_) => {}
                            Err(e) => tracing::warn!(
                                error = %e,
                                "memory-rank provenance retention sweep failed (non-fatal)"
                            ),
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            tracing::info!(
                                "memory-rank provenance sweep loop received shutdown signal"
                            );
                            break;
                        }
                    }
                }
            }
        });
    }

    // ---------- Embedding-model provenance: one-shot grandfather stamp ----------
    //
    // Legacy rows (embedding present, model NULL) are attributed to the
    // currently-configured EMBEDDING_MODEL on first boot after the
    // provenance migration; semantic reads are strict-equality on the
    // stamp from then on (see migration 20260720190000). Idempotent —
    // the predicate self-empties.
    {
        let gf_pool = db_pool.clone();
        tokio::spawn(async move {
            match talos_memory::grandfather_embedding_model(&gf_pool).await {
                Ok(n) if n > 0 => tracing::info!(
                    rows = n,
                    "embedding provenance: grandfathered actor_memory rows"
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    error = %e,
                    "embedding provenance grandfather (actor_memory) failed — \
                     legacy rows stay invisible to semantic reads until stamped"
                ),
            }
            match talos_ml::dataset::grandfather_examples_embedding_model(&gf_pool).await {
                Ok(n) if n > 0 => tracing::info!(
                    rows = n,
                    "embedding provenance: grandfathered ml_examples rows"
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    error = %e,
                    "embedding provenance grandfather (ml_examples) failed"
                ),
            }
        });
    }

    // ---------- Self-monitoring bridge: execution failures → ops_alerts ----------
    //
    // Cursor reconciler over terminal `workflow_executions` rows (see
    // `talos_ops_alerts_repository::self_monitor` for the design: why a
    // cursor beats finalizer hooks, the completed_at-vs-updated_at
    // choice, the safety lag, and the FOR UPDATE SKIP LOCKED
    // single-instance guard). Unattended failures become deduped
    // `source='talos'` ops alerts; a later green run auto-resolves
    // them. Kill switch TALOS_SELF_ALERTS=0; interval
    // TALOS_SELF_ALERTS_INTERVAL_SECS (default 60, clamped 5..=3600).
    if talos_ops_alerts_repository::self_monitor::self_alerts_enabled() {
        let self_monitor_pool = db_pool.clone();
        let self_monitor_shutdown = bg_shutdown_rx.clone();
        // Canonical env parsing (warns on non-positive garbage instead
        // of silently substituting — the zero-env-var footgun class).
        let self_monitor_interval: u64 = talos_config::positive_env_or_default(
            "TALOS_SELF_ALERTS_INTERVAL_SECS",
            talos_ops_alerts_repository::self_monitor::DEFAULT_TICK_INTERVAL_SECS,
        )
        .clamp(5, 3600);
        tokio::spawn(async move {
            let mut shutdown = self_monitor_shutdown;
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(self_monitor_interval));
            // Skip (not Burst, the default) missed ticks: after a
            // laptop sleep or long DB stall, ONE tick drains the whole
            // backlog internally — replaying ~60 queued ticks would
            // just hammer the cursor row with no-op transactions.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Burn the immediate first tick — nothing has finalized yet
            // this boot, and startup is busy enough.
            ticker.tick().await;
            tracing::info!(
                target: "talos_self_alerts",
                interval_secs = self_monitor_interval,
                "self-monitoring bridge reconciler started"
            );
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        talos_ops_alerts_repository::self_monitor::tick_and_log(
                            &self_monitor_pool,
                        )
                        .await;
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            tracing::info!("self-monitoring reconciler received shutdown signal");
                            break;
                        }
                    }
                }
            }
        });
    } else {
        tracing::info!(
            target: "talos_self_alerts",
            "self-monitoring bridge disabled via TALOS_SELF_ALERTS"
        );
    }

    // ---------- RFC 0010 P2 inc.4: dynamic worker-identity key refresh ---------
    //
    // Merges the DB-backed `worker_identities` registry into job_protocol's
    // dynamic verifying-key overlay (union with the static
    // `TALOS_WORKER_PUBLIC_KEYS` env base) so an autoscaling fleet can register
    // keys without an operator editing a ConfigMap. Verify-path reads are
    // lock-free (ArcSwap); this task just re-publishes the active set on an
    // interval, so max staleness for a rotation/revocation = one interval.
    //
    // Initial load is SYNCHRONOUS so DB-registered keys can verify the very first
    // job result after boot; a transient DB error there is non-fatal (env
    // registry stays live, the loop retries). `TALOS_WORKER_KEY_REFRESH_SECS=0`
    // disables the loop for deploys that use the env registry only.
    let worker_key_refresh_secs: u64 = std::env::var("TALOS_WORKER_KEY_REFRESH_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60);
    if worker_key_refresh_secs == 0 {
        tracing::info!(
            "Dynamic worker-identity key refresh disabled (TALOS_WORKER_KEY_REFRESH_SECS=0); \
             TALOS_WORKER_PUBLIC_KEYS env registry only"
        );
    } else {
        let refresh_secs = worker_key_refresh_secs.clamp(10, 3600);
        let worker_id_repo =
            talos_worker_identity_repository::WorkerIdentityRepository::new(db_pool.clone());
        let refresh_shutdown = bg_shutdown_rx.clone();
        tokio::spawn(async move {
            let mut shutdown = refresh_shutdown;
            // Immediate load so DB-registered keys go live shortly after boot; a
            // transient error here is non-fatal (env registry stays active, the
            // loop retries on the interval).
            match refresh_worker_key_overlay(&worker_id_repo).await {
                Ok(n) => tracing::info!(
                    target: "talos_engine",
                    event_kind = "worker_key_overlay_refresh",
                    installed = n,
                    "loaded dynamic worker-identity keys at boot"
                ),
                Err(e) => tracing::warn!(
                    target: "talos_engine",
                    error = %e,
                    "initial worker-identity key load failed; env registry still active, \
                     will retry on interval"
                ),
            }
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(refresh_secs));
            // Burn the immediate first tick — we just loaded above.
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Err(e) = refresh_worker_key_overlay(&worker_id_repo).await {
                            tracing::warn!(
                                target: "talos_engine",
                                error = %e,
                                "worker-identity key refresh failed; keeping last snapshot"
                            );
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            tracing::info!(
                                "worker-identity key refresh loop received shutdown signal"
                            );
                            break;
                        }
                    }
                }
            }
        });
    }

    // ---------- Audit-chain verification sweep (finding #2, Layer 2) ----------
    //
    // Continuously verifies the WORM audit ledger: each tick runs the offline
    // chain verifier over recently-completed executions and emits a loud
    // structured `audit_chain_verification_failed` event for any break
    // (tamper / deletion / reorder / bad HMAC). This is what turns "we CAN
    // verify the chain" into "we continuously DO" — the inline per-message
    // check (`talos_audit_ledger::verify_audit_message`) catches forgery at
    // ingest; this sweep catches gaps/deletions that only the full ordered
    // set reveals. Runs as a trusted system task on the bare pool (the audit
    // ledger is intentionally cross-tenant), so it needs no MCP/RBAC surface.
    //
    // Self-disables when no S3/WORM endpoint is configured (the from_env
    // helper returns None). Interval default 1h, clamped [300s, 86400s];
    // `AUDIT_CHAIN_SWEEP_INTERVAL_SECS=0` disables it. Lookback is 2× the
    // interval so window edges overlap (re-verification is idempotent); the
    // 120s settle floor skips just-finished executions whose audit events may
    // still be batching to S3, avoiding false sequence-gap reports.
    let audit_sweep_interval_secs: u64 = std::env::var("AUDIT_CHAIN_SWEEP_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3600);
    if audit_sweep_interval_secs == 0 {
        tracing::info!(
            "Audit-chain verification sweep disabled (AUDIT_CHAIN_SWEEP_INTERVAL_SECS=0)"
        );
    } else {
        let audit_sweep_interval_secs = audit_sweep_interval_secs.clamp(300, 86400);
        let audit_sweep_pool = db_pool.clone();
        let audit_sweep_shutdown = bg_shutdown_rx.clone();
        let lookback_secs = (audit_sweep_interval_secs as i64).saturating_mul(2);
        const SETTLE_SECS: i64 = 120;
        const MAX_EXECUTIONS_PER_SWEEP: i64 = 500;
        tokio::spawn(async move {
            let mut shutdown = audit_sweep_shutdown;
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(audit_sweep_interval_secs));
            // Burn the immediate first tick — at startup the most-recent
            // executions are still inside the settle window anyway.
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Some(stats) = talos_audit_ledger::run_chain_verification_sweep_from_env(
                            &audit_sweep_pool,
                            lookback_secs,
                            SETTLE_SECS,
                            MAX_EXECUTIONS_PER_SWEEP,
                        )
                        .await
                        {
                            if stats.failed > 0 || stats.errored > 0 {
                                tracing::warn!(
                                    target: "talos_audit",
                                    event_kind = "audit_chain_sweep_summary",
                                    scanned = stats.scanned,
                                    verified_ok = stats.verified_ok,
                                    failed = stats.failed,
                                    errored = stats.errored,
                                    "audit chain verification sweep completed WITH findings"
                                );
                            } else if stats.scanned > 0 {
                                tracing::info!(
                                    target: "talos_audit",
                                    event_kind = "audit_chain_sweep_summary",
                                    scanned = stats.scanned,
                                    verified_ok = stats.verified_ok,
                                    "audit chain verification sweep completed clean"
                                );
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            tracing::info!("Audit-chain verification sweep loop received shutdown signal");
                            break;
                        }
                    }
                }
            }
        });
    }

    // ---------- MCP-991: bcrypt cache revocation sweep ----------
    // Closes the residual revocation gap that the per-entry TTL can't
    // reach when `revoke_mcp_agent` deletes an `mcp_agents` row via
    // GraphQL. The cache lives in talos-mcp-handlers; talos-api can't
    // depend on it (workspace dep direction rule). The sweep runs
    // here at controller startup with the canonical db_pool — a
    // single batched query against ALL cached agent_ids drops the
    // revocation window from 10 s (TTL only) to ~3 s.
    crate::mcp::auth::spawn_bcrypt_cache_revocation_sweep(db_pool.clone(), bg_shutdown_rx.clone());

    // ---------- Phase 1.3 / Phase 5 residual reconciliation sweep ----------
    // Historical context: originally a dual-write safety net that mirrored
    // legacy table rows into the new `modules` table. Post-Phase-5 migration
    // all live write paths land directly in `modules` and the legacy tables
    // are frozen, so this sweep is a no-op in steady state — kept wired up
    // because the repository method is idempotent (ON CONFLICT DO NOTHING)
    // and it catches any stray residual row during the Phase 5 wind-down
    // window. Safe to remove after the legacy tables drop.
    {
        let recon_repo =
            std::sync::Arc::new(module_repository::ModuleRepository::new(db_pool.clone()));
        let recon_interval_secs: u64 = std::env::var("MODULES_RECONCILE_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(600)
            .clamp(60, 3600);
        // MCP-1042: subscribe to bg_shutdown_rx so SIGTERM exits the
        // sweep loop cleanly between ticks. Without this, an INSERT
        // statement issued mid-tick can wedge its connection-pool
        // entry on abort.
        let recon_shutdown = bg_shutdown_rx.clone();
        tokio::spawn(async move {
            let mut shutdown = recon_shutdown;
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(recon_interval_secs));
            // First tick fires immediately — sweep on startup so a fresh
            // boot picks up anything new without waiting one interval.
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        match recon_repo.reconcile_modules_table().await {
                            Ok((wasm_added, template_added)) => {
                                if wasm_added > 0 || template_added > 0 {
                                    tracing::info!(
                                        target: "talos_engine",
                                        event_kind = "modules_reconcile_sweep",
                                        wasm_added,
                                        template_added,
                                        interval_secs = recon_interval_secs,
                                        "mirrored legacy module rows into modules table"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    target: "talos_engine",
                                    error = %e,
                                    "modules-table reconciliation sweep failed"
                                );
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            tracing::info!(
                                target: "talos_engine",
                                "modules-table reconciliation sweep received shutdown signal"
                            );
                            break;
                        }
                    }
                }
            }
        });
        tracing::info!(
            target: "talos_engine",
            interval_secs = recon_interval_secs,
            "modules-table reconciliation sweep enabled"
        );
    }

    tracing::info!(
        "LLM-keys cache sweep loop started (interval: {}s)",
        sweep_interval_secs
    );
}

/// Cleanup / retention / archival sweeps (sessions, API keys, OAuth state
/// tokens, executions, audit logs, suspensions, WASM cache, webhook +
/// IP rate limiters, stuck executions), the one-shot crash-recovery resume
/// sweep (RFC 0003), the DEK cache cleanup, and the actor-memory TTL sweep.
/// Extracted verbatim from `main()`; spawn order preserved.
pub(crate) fn spawn_cleanup_tasks(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    nats_client: Option<std::sync::Arc<async_nats::Client>>,
    core: &CoreServices,
    services: &PlatformServices,
    limiters: &RateLimiters,
    bg_shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let secrets_manager = core.secrets_manager.clone();
    let registry = core.registry.clone();
    let auth_service = services.auth_service.clone();
    let api_key_service = services.api_key_service.clone();
    let oauth_service = services.oauth_service.clone();
    let webhook_router = services.webhook_router.clone();
    let module_execution_service = services.module_execution_service.clone();
    let worker_shared_key = services.worker_shared_key.clone();
    let auth_rate_limiter = services.auth_rate_limiter.clone();
    let api_limiter = limiters.api_limiter.clone();
    let webhook_limiter = limiters.webhook_limiter.clone();
    // ---------- Start background session cleanup task ----------
    // MCP-1043 (2026-05-15): the three auth-data DELETE sweeps below
    // (sessions / API keys / OAuth state tokens) now subscribe to
    // bg_shutdown_rx via tokio::select. Each issues
    // `DELETE FROM <credential_table>` statements; a mid-tick
    // SIGTERM abort can wedge the connection-pool entry on
    // Postgres-side until the server-side query timeout fires.
    // Same pattern as the canonical LLM-keys / bcrypt-cache /
    // stale_execution_cleanup (MCP-1042) sweeps.
    let cleanup_auth_service = auth_service.clone();
    let session_cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = session_cleanup_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match cleanup_auth_service.cleanup_expired_sessions().await {
                        Ok(count) => {
                            if count > 0 {
                                tracing::info!("Cleaned up {} expired sessions", count);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to cleanup expired sessions: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Session cleanup loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("Session cleanup task started (runs every 5 minutes)");

    // ---------- Start background API key cleanup task ----------
    let cleanup_api_key_service = api_key_service.clone();
    let api_key_cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = api_key_cleanup_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match cleanup_api_key_service.cleanup_expired_keys().await {
                        Ok(count) => {
                            if count > 0 {
                                tracing::info!("Deactivated {} expired API keys", count);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to cleanup expired API keys: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("API key cleanup loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("API key cleanup task started (runs every hour)");

    // ---------- Start background OAuth state token cleanup task ----------
    let cleanup_oauth_service = oauth_service.clone();
    let oauth_cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = oauth_cleanup_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match cleanup_oauth_service.cleanup_expired_state_tokens().await {
                        Ok(count) => {
                            if count > 0 {
                                tracing::info!("Cleaned up {} expired OAuth state tokens", count);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to cleanup expired OAuth state tokens: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("OAuth state token cleanup loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("OAuth state token cleanup task started (runs every hour)");

    // ---------- Start workflow execution cleanup task ----------
    let cleanup_pool = db_pool.clone();
    // MCP-622 (2026-05-12): use `talos_config::execution_retention_days()`
    // instead of a hardcoded `7`. Pre-fix the helper existed (defaulting
    // to 30) but had ZERO callers — operators who set
    // `EXECUTION_RETENTION_DAYS=90` thinking they were extending
    // retention had data silently deleted at 7 days. The
    // `execution_max_rows()` sibling helper also has no callers but is
    // not used by this task (separate ceiling concern). Cache the value
    // once at task start so a mid-process env mutation can't make the
    // window jitter unpredictably between iterations; operators
    // re-deploy to change retention.
    let retention_days = talos_config::execution_retention_days();
    // MCP-1044: subscribe to bg_shutdown_rx so SIGTERM exits the
    // retention-DELETE loop cleanly between top-level ticks. Inner
    // batched-DELETE chunks still run to natural completion within
    // one tick (5K-row chunks complete in seconds); the shutdown
    // select gates the OUTER 6-hour ticker only.
    let exec_retention_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = exec_retention_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Delete executions older than `retention_days` (skip queued executions).
                    // Batched in chunks of 5000 to avoid long-held row locks and
                    // WAL bloat on the first run (or after a long outage).
                    let mut total_deleted = 0u64;
                    loop {
                        match sqlx::query(
                            "DELETE FROM workflow_executions \
                             WHERE id IN ( \
                                 SELECT id FROM workflow_executions \
                                 WHERE started_at < NOW() - INTERVAL '1 day' * $1 \
                                   AND status != 'queued' \
                                 LIMIT 5000 \
                             )",
                        )
                        .bind(retention_days)
                        .execute(&cleanup_pool)
                        .await
                        {
                            Ok(result) => {
                                let batch = result.rows_affected();
                                total_deleted += batch;
                                if batch < 5000 {
                                    break; // last batch — done
                                }
                                // Yield between batches to avoid monopolising the pool.
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                            Err(e) => {
                                tracing::error!("Failed to cleanup old workflow executions: {}", e);
                                break;
                            }
                        }
                    }
                    if total_deleted > 0 {
                        tracing::info!(
                            "Cleaned up {} old workflow executions (older than {} days)",
                            total_deleted,
                            retention_days
                        );
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Workflow execution retention loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!(
        retention_days,
        "Workflow execution cleanup task started (runs every 6 hours, EXECUTION_RETENTION_DAYS)"
    );

    // ---------- Start execution archival task ----------
    // MCP-1044: subscribe to bg_shutdown_rx — this daily sweep issues
    // a transactional CTE that DELETEs from workflow_executions and
    // INSERTs into workflow_executions_archive in a single statement.
    // Mid-statement abort on SIGTERM would leave the transaction in
    // an uncommitted state (rolled back by Postgres) but the
    // connection-pool entry stuck until the server-side timeout. The
    // shutdown gate makes the exit point predictable.
    let archive_pool = db_pool.clone();
    let archive_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = archive_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400)); // daily
        loop {
            let tick_result = tokio::select! {
                _ = interval.tick() => Some(()),
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Execution archival loop received shutdown signal");
                        None
                    } else {
                        Some(())
                    }
                }
            };
            if tick_result.is_none() {
                break;
            }
            // Prefer DB setting over env var.
            // MCP-758 (2026-05-13): filter `db_days <= 0` so the DB-stored
            // override path matches the env-side hardening from MCP-643.
            // Pre-fix a `system_settings.value = 0` row took
            // db_days.unwrap_or(env_days) → 0, then bound 0 into
            // `make_interval(days => $1::int)` below — "completed_at < NOW() -
            // 0 days" matches every completed/failed/cancelled execution
            // ever, archiving the entire table at the next daily tick.
            // Negative DB values would have the same effect (Postgres
            // accepts negative make_interval; "older than -7 days" =
            // "older than now + 7 days" = also everything). Same =0
            // destructive class as MCP-703 (DB-stored fuel_budget) and
            // MCP-643 (env-side ARCHIVE_AFTER_DAYS). The DB row can be
            // written via admin SQL — there's no public API path that
            // sets it today, but defense-in-depth before a future admin
            // surface is cheap. Warn on the misconfiguration so an
            // operator who deliberately wrote 0/negative gets a clear
            // signal that the value was ignored.
            // MCP-961 sibling: saturating i64→i32 conversion. Sibling
            // of the advanced.rs fix — operator-supplied DB value
            // could exceed i32::MAX and silently wrap pre-fix.
            let db_days: Option<i32> = sqlx::query_scalar::<_, serde_json::Value>(
                "SELECT value FROM system_settings WHERE key = 'archive_after_days'",
            )
            .fetch_optional(&archive_pool)
            .await
            .unwrap_or(None)
            .and_then(|v| {
                v.as_i64()
                    .map(|n| i32::try_from(n).unwrap_or(i32::MAX))
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            });
            let env_days = talos_config::positive_env_or_default::<i32>("ARCHIVE_AFTER_DAYS", 30);
            let days = match db_days {
                Some(d) if d > 0 => d,
                Some(d) => {
                    tracing::warn!(
                        target: "talos_engine",
                        event_kind = "archive_after_days_nonpositive_substituted",
                        configured = d,
                        fallback = env_days,
                        "system_settings.archive_after_days = {} is non-positive — \
                         ignored to prevent archiving every completed execution; \
                         falling back to env-derived value",
                        d
                    );
                    env_days
                }
                None => env_days,
            };
            // Move old completed/failed/cancelled executions to archive
            let result = sqlx::query(
                "WITH archived AS (
                    DELETE FROM workflow_executions
                    WHERE status IN ('completed', 'failed', 'cancelled')
                    AND completed_at < NOW() - make_interval(days => $1::int)
                    AND is_pinned = false
                    RETURNING *
                )
                INSERT INTO workflow_executions_archive SELECT * FROM archived",
            )
            .bind(days)
            .execute(&archive_pool)
            .await;
            if let Ok(r) = result {
                if r.rows_affected() > 0 {
                    tracing::info!(count = r.rows_affected(), "Archived old executions");
                }
            }
        }
    });
    tracing::info!("Execution archival task started (runs daily, archives executions older than ARCHIVE_AFTER_DAYS env var, default 30)");

    // ---------- Start audit log cleanup task ----------
    // MCP-1045: subscribe to bg_shutdown_rx so SIGTERM exits the
    // hourly check loop cleanly. Audit log cleanup issues 3 DELETE
    // calls (auth + secret + webhook) once per day at 2 AM; outer
    // hourly ticker is what needs interruptibility.
    let cleanup_auth = auth_service.clone();
    let cleanup_secrets = secrets_manager.clone();
    let cleanup_webhooks = webhook_router.clone();
    let audit_cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = audit_cleanup_shutdown;
        // Run daily at 2 AM (check every hour, but only execute once per day)
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        let mut last_cleanup_day: Option<u32> = None;

        loop {
            let should_proceed = tokio::select! {
                _ = interval.tick() => true,
                _ = shutdown.changed() => !*shutdown.borrow(),
            };
            if !should_proceed {
                tracing::info!("Audit log cleanup loop received shutdown signal");
                break;
            }

            // Only run cleanup once per day at 2 AM
            use chrono::{Datelike, Timelike};
            let now = chrono::Utc::now();
            let current_day = now.ordinal(); // Day of year (1-indexed)
            let current_hour = now.hour();

            if current_hour == 2 && last_cleanup_day != Some(current_day) {
                // MCP-643: =0 would delete every audit log row (anything
                // older than 0 days = everything). Destructive class.
                let retention_days =
                    talos_config::positive_env_or_default::<i64>("AUDIT_LOG_RETENTION_DAYS", 90);

                tracing::info!(
                    "Starting audit log cleanup (retention: {} days)",
                    retention_days
                );

                // Clean up auth audit logs
                match cleanup_auth.cleanup_audit_logs(retention_days).await {
                    Ok(count) => {
                        if count > 0 {
                            tracing::info!("Cleaned up {} auth audit log entries", count);
                        }
                    }
                    Err(e) => tracing::error!("Failed to cleanup auth audit logs: {}", e),
                }

                // Clean up secret audit logs
                match cleanup_secrets.cleanup_audit_logs(retention_days).await {
                    Ok(count) => {
                        if count > 0 {
                            tracing::info!("Cleaned up {} secret audit log entries", count);
                        }
                    }
                    Err(e) => tracing::error!("Failed to cleanup secret audit logs: {}", e),
                }

                // Clean up webhook request logs
                match cleanup_webhooks.cleanup_request_logs(retention_days).await {
                    Ok(count) => {
                        if count > 0 {
                            tracing::info!("Cleaned up {} webhook request log entries", count);
                        }
                    }
                    Err(e) => tracing::error!("Failed to cleanup webhook request logs: {}", e),
                }

                // Clean up webhook dead-letter-queue rows. Dropped-request
                // payloads (DLP-redacted) accumulate forever without this
                // sweep — an unbounded storage-exhaustion vector under a
                // circuit-breaker / rate-limit flood against a known trigger.
                match cleanup_webhooks.cleanup_dlq(retention_days).await {
                    Ok(count) => {
                        if count > 0 {
                            tracing::info!("Cleaned up {} webhook DLQ entries", count);
                        }
                    }
                    Err(e) => tracing::error!("Failed to cleanup webhook DLQ: {}", e),
                }

                last_cleanup_day = Some(current_day);
                tracing::info!("Audit log cleanup completed");
            }
        }
    });
    tracing::info!("Audit log cleanup task started (runs daily at 2 AM)");

    // ---------- Expire timed-out workflow suspensions every 5 minutes ----------
    // MCP-1044: subscribe to bg_shutdown_rx — issues UPDATE
    // workflow_suspensions; mid-statement abort wedges the
    // connection pool until server-side timeout.
    let suspension_expiry_pool = db_pool.clone();
    let suspension_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = suspension_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match sqlx::query(
                        "UPDATE workflow_suspensions \
                         SET status = 'expired', resumed_by = 'timeout_expiry', resumed_at = now() \
                         WHERE status = 'waiting' AND timeout_at IS NOT NULL AND timeout_at < now()",
                    )
                    .execute(&suspension_expiry_pool)
                    .await
                    {
                        Ok(r) if r.rows_affected() > 0 => {
                            tracing::info!(
                                expired = r.rows_affected(),
                                "Expired timed-out workflow suspensions"
                            );
                        }
                        Err(e) => tracing::error!("Failed to expire workflow suspensions: {}", e),
                        _ => {}
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Suspension expiry loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("Suspension expiry task started (runs every 5 minutes)");

    // ---------- Start WASM module cache cleanup task ----------
    let cleanup_registry = registry.clone();
    tokio::spawn(async move {
        // Run every 6 hours
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(21600));

        loop {
            interval.tick().await;

            // MCP-643: =0 on any of these would purge the entire WASM
            // cache on the next sweep (retention=0 days, max=0 entries,
            // size cap=0 MB). Recoverable (re-pull from OCI) but
            // operationally costly. Substitute defaults + WARN.
            let retention_days =
                talos_config::positive_env_or_default::<i64>("WASM_CACHE_RETENTION_DAYS", 30);
            let max_modules =
                talos_config::positive_env_or_default::<i64>("WASM_CACHE_MAX_MODULES", 1000);
            let max_size_mb =
                talos_config::positive_env_or_default::<i64>("WASM_CACHE_MAX_SIZE_MB", 500);

            // Clean up old modules
            match cleanup_registry.cleanup_old_modules(retention_days).await {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!(
                            "Cleaned up {} old WASM modules (>{}d)",
                            count,
                            retention_days
                        );
                    }
                }
                Err(e) => tracing::error!("Failed to cleanup old WASM modules: {}", e),
            }

            // Enforce cache size limits
            match cleanup_registry
                .enforce_cache_limits(max_modules, max_size_mb)
                .await
            {
                Ok((modules_deleted, bytes_freed)) => {
                    if modules_deleted > 0 || bytes_freed > 0 {
                        tracing::info!(
                            "Evicted {} WASM modules (freed {} modules, {} MB)",
                            modules_deleted,
                            modules_deleted,
                            bytes_freed
                        );
                    }
                }
                Err(e) => tracing::error!("Failed to enforce WASM cache limits: {}", e),
            }

            // Log cache stats
            match cleanup_registry.get_cache_stats().await {
                Ok(stats) => {
                    tracing::debug!(
                        "WASM cache stats: {} modules, {:.2} MB, {} total uses",
                        stats.module_count,
                        stats.total_size_mb,
                        stats.total_usage_count
                    );
                }
                Err(e) => tracing::error!("Failed to get WASM cache stats: {}", e),
            }
        }
    });
    tracing::info!("WASM cache cleanup task started (runs every 6 hours)");

    // ---------- Start webhook rate-limiter + circuit-breaker cleanup task ----------
    // Prevents unbounded growth of in-memory token buckets and CB records as unique
    // webhook tokens and IPs accumulate over the process lifetime.
    let cleanup_webhook_rl = webhook_router.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Every 5 min
        loop {
            interval.tick().await;
            cleanup_webhook_rl.cleanup_rate_limiter();
            cleanup_webhook_rl.cleanup_circuit_breaker();
        }
    });
    tracing::info!(
        "Webhook rate-limiter + circuit-breaker cleanup task started (runs every 5 minutes)"
    );

    // ---------- Start IP rate-limiter cleanup task (MCP-694) ----------
    // The governor `RateLimiter<String, DashMapStateStore<String>>` for
    // `api_limiter` and `webhook_limiter` retains one DashMap entry per
    // distinct source IP forever. Under sustained traffic from many
    // distinct IPs (botnet sweeps, public internet exposure) the maps
    // grow without bound — at ~150 bytes per entry, 1M unique IPs
    // ≈ 150 MB per limiter. `retain_recent()` drops keys whose buckets
    // are indistinguishable from a "fresh" state (idle long enough that
    // they hit no rate-limit cost on next encounter); `shrink_to_fit()`
    // reclaims the DashMap capacity. Both are governor-provided
    // (governor 0.6.3 src/state/keyed.rs:180,191).
    //
    // Same 5-min cadence as the webhook cleanup above so operators see
    // one consistent rate-limiter-hygiene heartbeat in logs.
    let cleanup_api_limiter = api_limiter.clone();
    let cleanup_webhook_ip_limiter = webhook_limiter.clone();
    // MCP-718 (2026-05-13): add the `DistributedRateLimiter`'s in-memory
    // fallback to the same sweep. Under FailOpen Redis outages the
    // fallback accumulates one DashMap entry per distinct auth-attempt
    // identifier; entries SURVIVE Redis recovery (governor's keyed
    // state store has no auto-eviction). Wiring through the new
    // `cleanup_fallback()` helper keeps the contract identical to the
    // raw-limiter sweep above without leaking the inner `IpRateLimiter`
    // out of `DistributedRateLimiter`.
    let cleanup_auth_limiter = auth_rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        // First tick fires immediately — burn it so a fresh boot doesn't
        // do an empty-map walk before any request has been admitted.
        interval.tick().await;
        loop {
            interval.tick().await;
            let api_before = cleanup_api_limiter.len();
            cleanup_api_limiter.retain_recent();
            cleanup_api_limiter.shrink_to_fit();
            let api_after = cleanup_api_limiter.len();

            let wh_before = cleanup_webhook_ip_limiter.len();
            cleanup_webhook_ip_limiter.retain_recent();
            cleanup_webhook_ip_limiter.shrink_to_fit();
            let wh_after = cleanup_webhook_ip_limiter.len();

            let auth_before = cleanup_auth_limiter.fallback_len();
            cleanup_auth_limiter.cleanup_fallback();
            let auth_after = cleanup_auth_limiter.fallback_len();

            if api_before > api_after || wh_before > wh_after || auth_before > auth_after {
                tracing::info!(
                    target: "talos_rate_limit",
                    event_kind = "ip_rate_limiter_sweep",
                    api_before, api_after,
                    webhook_before = wh_before,
                    webhook_after = wh_after,
                    auth_fallback_before = auth_before,
                    auth_fallback_after = auth_after,
                    "IP rate-limiter cleanup: dropped idle buckets"
                );
            }
        }
    });
    tracing::info!(
        "IP rate-limiter cleanup task started (runs every 5 minutes, retain_recent + shrink_to_fit; covers api + webhook + auth-fallback)"
    );

    // ---------- Start stuck execution cleanup task ----------
    // Transitions orphaned `pending`/`running` executions to `timeout` when a
    // worker crashes without reporting a result.
    //
    // MCP-1044: subscribe to bg_shutdown_rx — issues
    // UPDATE workflow_executions; mid-statement abort wedges the
    // connection pool. Same MCP-1042/1043 discipline.
    let cleanup_exec_service = module_execution_service.clone();
    let stuck_cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = stuck_cleanup_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // MCP-643: =0 would mark every running execution as stuck
                    // immediately (anything older than 0 mins = everything),
                    // including healthy in-progress jobs.
                    let max_age_mins =
                        talos_config::positive_env_or_default::<i64>("STUCK_EXECUTION_TIMEOUT_MINS", 30);
                    match cleanup_exec_service
                        .cleanup_stuck_executions(max_age_mins)
                        .await
                    {
                        Ok(count) if count > 0 => tracing::warn!(
                            "Cleaned up {} stuck executions (idle > {} min)",
                            count,
                            max_age_mins
                        ),
                        Ok(_) => {}
                        Err(e) => tracing::error!("Failed to cleanup stuck executions: {}", e),
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Stuck execution cleanup loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("Stuck execution cleanup task started (runs every 5 minutes, timeout after 30 min by default)");

    // ---------- Crash recovery: resume checkpointed executions ----------
    // RFC 0003 (durable execution). On a controller restart, executions that
    // were mid-flight are wedged in `running` — their in-process engine task
    // died with the process. When EXECUTION_CHECKPOINTING_ENABLED is on, the
    // engine persisted node-result checkpoints; this one-shot startup sweep
    // claims those orphans (`running -> resuming`, FOR UPDATE SKIP LOCKED so
    // it's exactly-once across replicas) and resumes each from its last
    // checkpoint via the NATS seed path.
    //
    // ONE-SHOT at startup (not periodic) on purpose: at startup there are no
    // live in-process engine tasks from THIS process, so any orphaned
    // `running` row is genuinely dead. A periodic sweep in a single-replica
    // deployment could claim a long-running-but-alive execution (one whose
    // current node runs longer than the stale window without a checkpoint
    // heartbeat) and double-dispatch it.
    //
    // Requires NATS (the resume dispatch goes over signed NATS-RPC) and the
    // checkpointing flag — without checkpoints there is nothing to resume.
    if talos_config::bool_env_or_default("EXECUTION_CHECKPOINTING_ENABLED", false) {
        if let Some(nats_for_recovery) = nats_client.clone() {
            // Resume orphans idle beyond this window. MUST be smaller than
            // STUCK_EXECUTION_TIMEOUT_MINS (default 30) so a recoverable
            // execution is resumed before any cleanup path could fail it.
            let resume_stale_mins =
                talos_config::positive_env_or_default::<i64>("EXECUTION_RESUME_STALE_MINS", 5);
            let stuck_timeout_mins =
                talos_config::positive_env_or_default::<i64>("STUCK_EXECUTION_TIMEOUT_MINS", 30);
            if resume_stale_mins >= stuck_timeout_mins {
                tracing::warn!(
                    resume_stale_mins,
                    stuck_timeout_mins,
                    "EXECUTION_RESUME_STALE_MINS >= STUCK_EXECUTION_TIMEOUT_MINS — orphaned \
                     executions may be failed by stuck-cleanup before crash recovery can claim them"
                );
            }
            let recovery_deps = talos_execution_orchestration::RecoveryDeps {
                db_pool: db_pool.clone(),
                registry: registry.clone(),
                secrets_manager: secrets_manager.clone(),
                actor_repo: std::sync::Arc::new(actor_repository::ActorRepository::new(
                    db_pool.clone(),
                )),
                execution_repo: std::sync::Arc::new(
                    crate::execution_repository::ExecutionRepository::new(db_pool.clone()),
                ),
                worker_shared_key: worker_shared_key.clone(),
                nats_client: nats_for_recovery,
            };
            tokio::spawn(async move {
                talos_execution_orchestration::recover_stuck_executions(
                    recovery_deps,
                    resume_stale_mins,
                )
                .await;
            });
            tracing::info!(
                "Crash-recovery startup sweep spawned (EXECUTION_CHECKPOINTING_ENABLED on); \
                 resuming executions idle > {} min from their last checkpoint",
                resume_stale_mins
            );
        } else {
            tracing::warn!(
                "EXECUTION_CHECKPOINTING_ENABLED is on but NATS is unavailable — \
                 crash-recovery sweep skipped (resume dispatch needs NATS)"
            );
        }
    }

    // ---------- Start DEK cache cleanup task ----------
    // Evicts expired DEK entries from the in-memory HashMap to prevent unbounded
    // growth in long-lived processes.  DEK rotation is rare, so the cache stays
    // small in practice, but the cleanup ensures stale entries are released.
    let cleanup_secrets_dek = secrets_manager.clone();
    tokio::spawn(async move {
        // Run every 10 minutes — DEK TTL is 5 min by default, so this evicts
        // entries within one extra TTL period of expiry.
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
        loop {
            interval.tick().await;
            cleanup_secrets_dek.cleanup_expired_cache_entries().await;
        }
    });
    tracing::info!("DEK cache cleanup task started (runs every 10 minutes)");

    // ---------- Start actor memory TTL cleanup task ----------
    // Deletes expired actor_memory rows (working=1h, episodic=7d,
    // scratchpad=24h TTLs stored in expires_at; semantic rows never
    // expire). Goes through `talos_memory::sweep_expired` so the
    // single canonical service owns every direct write to the
    // table — no inline DELETE queries elsewhere in the codebase.
    let agent_memory_pool = db_pool.clone();
    let actor_memory_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = actor_memory_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(900)); // Every 15 min
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Grace = 0: expired rows are deleted immediately on each
                    // tick. Override here if we ever want to retain
                    // tombstones longer than their TTL for forensics.
                    match talos_memory::sweep_expired(&agent_memory_pool, 0).await {
                        Ok(0) => {}
                        Ok(n) => tracing::debug!(count = n, "Cleaned up expired actor_memory entries"),
                        Err(e) => tracing::error!("Failed to cleanup actor_memory TTL: {}", e),
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Actor-memory TTL sweep loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("Actor memory TTL cleanup task started (runs every 15 minutes)");
}

/// Actor-memory embedding backfill (one-shot), readiness-score
/// recomputation, and SLA degradation alerting. Extracted verbatim from
/// `main()`; spawn order preserved.
pub(crate) fn spawn_analytics_tasks(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    bg_shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    // ---------- Start actor memory embedding backfill (one-shot on startup) ----------
    {
        let backfill_pool = db_pool.clone();
        tokio::spawn(async move {
            // Small delay to let Ollama warm up after restart.
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            match actor_memory_service::backfill_embeddings(&backfill_pool, 100).await {
                Ok(n) => {
                    if n > 0 {
                        tracing::info!(embedded = n, "Actor memory embedding backfill completed");
                    }
                }
                Err(e) => tracing::warn!("Actor memory embedding backfill failed: {}", e),
            }
        });
    }

    // ---------- Start readiness score background recomputation task ----------
    // MCP-1045: subscribe to bg_shutdown_rx — issues per-workflow
    // UPDATE actor_readiness statements; mid-batch SIGTERM aborts
    // can leave readiness rows partially updated and wedge the
    // connection-pool entry on the in-flight UPDATE.
    let readiness_pool = db_pool.clone();
    let readiness_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = readiness_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Every hour
        loop {
            let should_proceed = tokio::select! {
                _ = interval.tick() => true,
                _ = shutdown.changed() => !*shutdown.borrow(),
            };
            if !should_proceed {
                tracing::info!("Readiness recomputation loop received shutdown signal");
                break;
            }

            // Fetch all workflows with stale or missing readiness scores
            let workflows: Vec<(
                uuid::Uuid,
                uuid::Uuid,
                Option<String>,
                Vec<String>,
                Option<String>,
            )> = match sqlx::query_as(
                "SELECT id, user_id, description, capabilities, graph_json \
                 FROM workflows \
                 WHERE readiness_computed_at IS NULL \
                    OR readiness_computed_at < NOW() - INTERVAL '1 hour' \
                 LIMIT 500",
            )
            .fetch_all(&readiness_pool)
            .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::error!("Readiness score batch query failed: {}", e);
                    continue;
                }
            };

            if workflows.is_empty() {
                continue;
            }

            let mut updated = 0u64;
            // MCP-778 (2026-05-13): track UPDATE failures alongside successes
            // so the operator-facing summary surfaces partial-batch DB issues.
            // See the `if updated > 0` log at the loop tail.
            let mut update_failed = 0u64;
            for (wf_id, wf_user_id, wf_desc, wf_caps, graph_json_str) in &workflows {
                let graph: serde_json::Value = graph_json_str
                    .as_deref()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or_else(|| serde_json::json!({"nodes":[],"edges":[]}));

                // Reliability (50%): success_rate * min(exec_count/10, 1.0)
                // Saturates at 10 runs — consistent with get_readiness_breakdown handler.
                // 5 perfect runs → 50% reliability credit (not alarming on operator dashboards).
                //
                // MCP-503: pair every `.unwrap_or` zero-fallback in this
                // background task with a `tracing::warn!`. Pre-fix the
                // inner queries silently swallowed DB errors, so a
                // column rename / FK violation / schema drift would
                // quietly downgrade every workflow's readiness score
                // with no operator-visible signal. Same lint-check-8
                // pattern fixed in MCP-488 (cost-attribution) and
                // MCP-489 (retry-intelligence). The outer batch query
                // at line ~1691 ALREADY logs-and-continues; this fix
                // brings the inner queries to parity.
                let perf_row: Option<(Option<f64>, i64)> = sqlx::query_as(
                    "SELECT \
                        (COUNT(*) FILTER (WHERE status = 'completed'))::float / NULLIF(COUNT(*), 0), \
                        COUNT(*) \
                     FROM workflow_executions \
                     WHERE workflow_id = $1 AND started_at > NOW() - interval '30 days'"
                ).bind(wf_id).fetch_optional(&readiness_pool).await.unwrap_or_else(|e| {
                    tracing::warn!(
                        %wf_id,
                        error = %e,
                        "readiness: workflow_executions perf query failed — using neutral reliability"
                    );
                    None
                });

                let (success_rate, exec_count) = perf_row.unwrap_or((None, 0));
                let reliability =
                    success_rate.unwrap_or(0.0) * (exec_count as f64 / 10.0).min(1.0) * 50.0;

                // Documentation (20%): has_desc=10, has_node_desc=5, has_caps=5
                // Consistent with get_readiness_breakdown handler.
                let has_desc = if wf_desc.as_ref().map(|d| !d.is_empty()).unwrap_or(false) {
                    10.0
                } else {
                    0.0
                };
                let has_node_desc = if graph
                    .get("nodes")
                    .and_then(|n| n.as_array())
                    .map(|nodes| {
                        nodes.iter().any(|n| {
                            n.get("description")
                                .and_then(|d| d.as_str())
                                .map(|s| !s.is_empty())
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false)
                {
                    5.0
                } else {
                    0.0
                };
                let has_caps = if !wf_caps.is_empty() { 5.0 } else { 0.0 };
                let documentation = has_desc + has_node_desc + has_caps;

                // Freshness (20%)
                let last_exec: Option<(Option<chrono::DateTime<chrono::Utc>>,)> = sqlx::query_as(
                    "SELECT MAX(started_at) FROM workflow_executions WHERE workflow_id = $1",
                )
                .bind(wf_id)
                .fetch_optional(&readiness_pool)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(
                        %wf_id,
                        error = %e,
                        "readiness: workflow_executions last-exec query failed — freshness scored 0"
                    );
                    None
                });

                let freshness = match last_exec.and_then(|r| r.0) {
                    Some(last) => {
                        let days_ago = chrono::Utc::now().signed_duration_since(last).num_days();
                        if days_ago <= 7 {
                            20.0
                        } else if days_ago <= 30 {
                            10.0
                        } else {
                            0.0
                        }
                    }
                    None => 0.0,
                };

                // Risk (10%)
                let has_timeout = graph.get("execution_timeout_secs").is_some();
                let has_error_edges = graph
                    .get("edges")
                    .and_then(|e| e.as_array())
                    .map(|edges| {
                        edges
                            .iter()
                            .any(|e| e.get("edge_type").and_then(|t| t.as_str()) == Some("error"))
                    })
                    .unwrap_or(false);
                let expiring_secrets: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM secrets WHERE created_by = $1 AND expires_at IS NOT NULL AND expires_at < NOW() + interval '7 days'"
                ).bind(wf_user_id).fetch_one(&readiness_pool).await.unwrap_or_else(|e| {
                    tracing::warn!(
                        %wf_user_id,
                        error = %e,
                        "readiness: expiring-secrets query failed — risk score will not reflect expiry"
                    );
                    0
                });

                let mut risk = 10.0_f64;
                if !has_timeout {
                    risk -= 3.0;
                }
                if !has_error_edges {
                    risk -= 3.0;
                }
                if expiring_secrets > 0 {
                    risk -= 4.0;
                }
                let risk = risk.max(0.0);

                let total = (reliability + documentation + freshness + risk).round() as i32;

                // MCP-778 (2026-05-13): replace `.is_ok()` swallow with a
                // success/failure split. Pre-fix the UPDATE error was
                // discarded — under sustained DB pressure (long-running
                // statement timeout, FK churn, partition lock), the
                // background recomputation showed "Recomputed readiness
                // scores for 0 workflows" even though hundreds of UPDATEs
                // were attempted-and-failed. Operators saw stale dashboard
                // readiness scores with NO log signal correlating the
                // staleness to DB health. Same MCP-503 observability rule
                // applied to the read-side queries in this same task
                // (line ~1911); this brings the write-side to parity.
                // High-volume loop → log a SUMMARY at end (not per-row)
                // to avoid spamming.
                match sqlx::query(
                    "UPDATE workflows SET readiness_score = $1, readiness_computed_at = NOW() WHERE id = $2"
                )
                .bind(total)
                .bind(wf_id)
                .execute(&readiness_pool)
                .await
                {
                    Ok(_) => updated += 1,
                    Err(_) => update_failed += 1,
                }
            }

            if updated > 0 || update_failed > 0 {
                if update_failed == 0 {
                    tracing::info!(
                        target: "talos_audit",
                        updated,
                        "Recomputed readiness scores for {} workflows", updated
                    );
                } else {
                    tracing::warn!(
                        target: "talos_audit",
                        updated,
                        update_failed,
                        total_processed = updated + update_failed,
                        "Recomputed readiness scores: {} succeeded, {} UPDATE failures — DB may be under pressure; readiness dashboard will show stale scores for the failed rows until next hourly tick",
                        updated,
                        update_failed
                    );
                }
            }
        }
    });
    tracing::info!("Readiness score recomputation task started (runs every hour)");

    // ---------- Start SLA degradation alerting task ----------
    // MCP-1045: subscribe to bg_shutdown_rx — issues INSERTs into
    // workflow_sla_alerts on threshold breach. Outer 15-min ticker
    // gated; inner per-workflow alert-emit loop runs to natural
    // completion within one tick.
    let sla_pool = db_pool.clone();
    let sla_degradation_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = sla_degradation_shutdown;
        // Wait 2 minutes after startup before first check to let executions settle
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(900)); // 15 min
                                                                                       // MCP-469: disable redirect following for SLA notification
                                                                                       // webhooks. The SSRF check at fire time validates the literal
                                                                                       // URL, but reqwest's default `Policy::limited(10)` would follow
                                                                                       // a 302/303 to an internal host beneath the SSRF gate. Matches
                                                                                       // the canonical pattern in approval_gate / failure_webhook.
                                                                                       //
                                                                                       // Fallback to `Client::new()` removed: that path re-enabled the
                                                                                       // default redirect policy and would silently reopen the SSRF
                                                                                       // gap. `.build()` rarely fails (TLS init issues only), and
                                                                                       // `Client::new()` would also panic on the same failure mode —
                                                                                       // so a loud `.expect()` is functionally equivalent and removes
                                                                                       // the false sense of recovery.
                                                                                       // MCP-1034: explicit connect_timeout (2s on 5s budget) so a
                                                                                       // black-holed SLA-webhook endpoint fails on connect rather than
                                                                                       // burning the whole loop tick.
                                                                                       // Built via the shared SSRF-safe builder: redirect(none) + the
                                                                                       // connect-time ControllerSsrfResolver. The SLA-alert webhook URL is
                                                                                       // user/workflow-supplied (SLA threshold config) and SSRF-checked at fire
                                                                                       // time, but that call-time check can't stop DNS rebinding — the same gap
                                                                                       // PR #162 closed for the sibling fire sites.
        let http_client = talos_http_utils::outbound::build_outbound_webhook_client_with_timeout(
            "talos-sla-webhook/1.0",
            std::time::Duration::from_secs(5),
        )
        .expect("SLA monitor: failed to build HTTP client with no-redirect policy");
        let analytics_repo = analytics_repository::AnalyticsRepository::new(sla_pool.clone());

        loop {
            let should_proceed = tokio::select! {
                _ = interval.tick() => true,
                _ = shutdown.changed() => !*shutdown.borrow(),
            };
            if !should_proceed {
                tracing::info!("SLA degradation alerting loop received shutdown signal");
                break;
            }

            // 1. Check workflows with explicit SLA thresholds
            let sla_rows: Vec<(
                uuid::Uuid,
                uuid::Uuid,
                String,
                Option<f64>,
                Option<f64>,
                Option<String>,
            )> = match sqlx::query_as(
                "SELECT t.workflow_id, w.user_id, w.name, \
                            t.success_rate_pct::float8, t.p95_latency_ms::float8, \
                            t.notification_webhook \
                     FROM workflow_sla_thresholds t \
                     JOIN workflows w ON w.id = t.workflow_id \
                     LIMIT 500",
            )
            .fetch_all(&sla_pool)
            .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::error!("SLA check: failed to fetch thresholds: {}", e);
                    continue;
                }
            };

            for (wf_id, wf_user_id, wf_name, target_rate, target_p95, webhook) in &sla_rows {
                // Use centralized AnalyticsRepository::get_sla_window_stats so
                // SLA alerting and readiness scoring share identical PERCENTILE
                // computations.
                let stats = match analytics_repo.get_sla_window_stats(*wf_id, 24).await {
                    Some(s) if s.total >= 3 => s, // Minimum volume: 3 executions
                    _ => continue,
                };
                let (total, successes, p95_ms) = (stats.total, stats.successes, stats.p95_ms);

                let actual_rate = (successes as f64 / total as f64) * 100.0;

                // Check success rate SLA
                if let Some(target) = target_rate {
                    if actual_rate < *target {
                        let msg = format!(
                            "SLA violation: {} success rate {:.1}% < threshold {:.1}% (last 24h, {}/{})",
                            wf_name, actual_rate, target, successes, total
                        );
                        // Create alert (dedup handles repeated violations).
                        // If the alert insert fails, the next tick won't see
                        // the existing dedup row and would re-insert — log
                        // so the dedup behavior is observable.
                        // N-L (2026-05-06): snapshot workflow_name into the
                        // alert row so the operator dashboard surfaces the
                        // name even after the workflow is deleted.
                        if let Err(e) = sqlx::query(
                            "INSERT INTO workflow_alerts (id, user_id, workflow_id, execution_id, alert_type, message, workflow_name) \
                             VALUES ($1, $2, $3, $4, 'sla_violation', $5, $6) \
                             ON CONFLICT (workflow_id, message) WHERE acknowledged = false \
                             DO UPDATE SET occurrence_count = workflow_alerts.occurrence_count + 1, \
                                          last_occurred_at = NOW()",
                        )
                        .bind(uuid::Uuid::new_v4())
                        .bind(wf_user_id)
                        .bind(wf_id)
                        .bind(uuid::Uuid::nil()) // no specific execution
                        .bind(&msg)
                        .bind(wf_name)
                        .execute(&sla_pool)
                        .await
                        {
                            tracing::error!(
                                workflow_id = %wf_id,
                                error = %e,
                                "SLA monitor: failed to insert/dedup workflow_alert (success-rate)"
                            );
                        }

                        tracing::warn!(workflow = %wf_name, actual = actual_rate, target = target, "SLA violation detected");

                        // Fire notification webhook if configured
                        if let Some(url) = webhook {
                            if !url.is_empty()
                                && mcp::utils::check_outbound_url_no_ssrf(url).is_ok()
                            {
                                let payload = serde_json::json!({
                                    "event": "sla_violation",
                                    "workflow_id": wf_id,
                                    "workflow_name": wf_name,
                                    "metric": "success_rate",
                                    "actual": actual_rate,
                                    "threshold": target,
                                    "period": "24h",
                                    "timestamp": chrono::Utc::now().to_rfc3339()
                                });
                                let client = http_client.clone();
                                let url = url.clone();
                                // MCP-774 (2026-05-13): log delivery failures
                                // on the SLA-degradation webhook fire. Pre-fix
                                // `let _ = ...await` discarded both Ok-status
                                // and Err — if the operator's notification
                                // endpoint (PagerDuty / Slack / incident-mgmt)
                                // was unreachable (DNS / TLS / 5xx / network
                                // partition), the SLA violation was DETECTED
                                // and ALERTED locally (via workflow_alerts
                                // INSERT above) but NEVER delivered, with zero
                                // log signal correlating the delivery failure
                                // to controller health. Same operator-visibility
                                // class as MCP-742 (failure_webhook.rs sibling)
                                // and MCP-733..746. The 5-minute SLA threshold
                                // breach task in this same file (~line 3729 /
                                // 3756) already follows the canonical shape;
                                // this 15-minute degradation task was drifted.
                                tokio::spawn(async move {
                                    match client.post(&url).json(&payload).send().await {
                                        Ok(resp) if resp.status().is_success() => {
                                            tracing::debug!(
                                                webhook = %url,
                                                status = resp.status().as_u16(),
                                                "SLA-degradation webhook delivered"
                                            );
                                        }
                                        Ok(resp) => {
                                            tracing::warn!(
                                                target: "talos_rpc",
                                                webhook = %url,
                                                status = resp.status().as_u16(),
                                                "SLA-degradation webhook returned non-success status — operator notification may not have reached its destination"
                                            );
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                target: "talos_rpc",
                                                webhook = %url,
                                                error = %e,
                                                "SLA-degradation webhook POST failed — operator notification undelivered"
                                            );
                                        }
                                    }
                                });
                            }
                        }
                    }
                }

                // Check p95 latency SLA
                if let (Some(target), Some(actual)) = (target_p95, p95_ms) {
                    if actual > *target {
                        let msg = format!(
                            "SLA violation: {} p95 latency {:.0}ms > threshold {:.0}ms (last 24h)",
                            wf_name, actual, target
                        );
                        // N-L: workflow_name snapshot, see above.
                        if let Err(e) = sqlx::query(
                            "INSERT INTO workflow_alerts (id, user_id, workflow_id, execution_id, alert_type, message, workflow_name) \
                             VALUES ($1, $2, $3, $4, 'sla_violation', $5, $6) \
                             ON CONFLICT (workflow_id, message) WHERE acknowledged = false \
                             DO UPDATE SET occurrence_count = workflow_alerts.occurrence_count + 1, \
                                          last_occurred_at = NOW()",
                        )
                        .bind(uuid::Uuid::new_v4())
                        .bind(wf_user_id)
                        .bind(wf_id)
                        .bind(uuid::Uuid::nil())
                        .bind(&msg)
                        .bind(wf_name)
                        .execute(&sla_pool)
                        .await
                        {
                            tracing::error!(
                                workflow_id = %wf_id,
                                error = %e,
                                "SLA monitor: failed to insert/dedup workflow_alert (p95-latency)"
                            );
                        }
                    }
                }
            }

            // 2. Catch catastrophic failures for workflows WITHOUT explicit thresholds
            // Alert when success rate < 50% with at least 5 executions in the last 24h
            let catastrophic: Vec<(uuid::Uuid, uuid::Uuid, String, i64, i64)> = sqlx::query_as(
                "SELECT w.id, w.user_id, w.name, \
                        COUNT(*), \
                        COUNT(*) FILTER (WHERE we.status = 'completed') \
                 FROM workflows w \
                 JOIN workflow_executions we ON we.workflow_id = w.id \
                 WHERE we.started_at > NOW() - INTERVAL '24 hours' \
                   AND w.status = 'active' \
                   AND w.id NOT IN (SELECT workflow_id FROM workflow_sla_thresholds) \
                 GROUP BY w.id, w.user_id, w.name \
                 HAVING COUNT(*) >= 5 \
                    AND (COUNT(*) FILTER (WHERE we.status = 'completed'))::float / COUNT(*) < 0.5 \
                 LIMIT 100",
            )
            .fetch_all(&sla_pool)
            .await
            .unwrap_or_default();

            for (wf_id, wf_user_id, wf_name, total, successes) in &catastrophic {
                let rate = (*successes as f64 / *total as f64) * 100.0;
                let msg = format!(
                    "Catastrophic failure rate: {} at {:.1}% success ({}/{} in 24h). \
                     Set an SLA threshold with set_workflow_sla_threshold to customize alerting.",
                    wf_name, rate, successes, total
                );
                if let Err(e) = sqlx::query(
                    "INSERT INTO workflow_alerts (id, user_id, workflow_id, execution_id, alert_type, message) \
                     VALUES ($1, $2, $3, $4, 'catastrophic_failure_rate', $5) \
                     ON CONFLICT (workflow_id, message) WHERE acknowledged = false \
                     DO UPDATE SET occurrence_count = workflow_alerts.occurrence_count + 1, \
                                  last_occurred_at = NOW()",
                )
                .bind(uuid::Uuid::new_v4())
                .bind(wf_user_id)
                .bind(wf_id)
                .bind(uuid::Uuid::nil())
                .bind(&msg)
                .execute(&sla_pool)
                .await
                {
                    tracing::error!(
                        workflow_id = %wf_id,
                        error = %e,
                        "SLA monitor: failed to insert/dedup workflow_alert (catastrophic-failure)"
                    );
                }

                tracing::warn!(workflow = %wf_name, success_rate = rate, "Catastrophic failure rate detected");
            }
        }
    });
    tracing::info!("SLA degradation alerting task started (runs every 15 minutes)");
}

/// Gmail watch renewal, Google Calendar channel renewal, and the OAuth
/// proactive token refresh loops. Extracted verbatim from `main()`; spawn
/// order preserved.
pub(crate) fn spawn_integration_renewal_tasks(
    services: &PlatformServices,
    bg_shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let gmail_watch_service = services.gmail_watch_service.clone();
    let google_calendar_service = services.google_calendar_service.clone();
    let oauth_credential_service = services.oauth_credential_service.clone();
    // ---------- Start Gmail watch renewal task ----------
    if let Some(ref gmail_watch) = gmail_watch_service {
        let renewal = gmail_watch.clone();
        let gmail_renewal_shutdown = bg_shutdown_rx.clone();
        tokio::spawn(async move {
            gmail::scheduler::gmail_renewal_task(renewal, gmail_renewal_shutdown).await;
        });
        tracing::info!("Gmail watch renewal task started (runs every hour)");

        // Sweep the per-(user,integration) create-lock map hourly so
        // it doesn't grow unbounded in a long-running controller.
        let cleanup_gmail = gmail_watch.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                cleanup_gmail.cleanup_create_locks();
            }
        });
    }

    // ---------- GCP watch create-lock sweep ----------
    // No renewal task for GCP (the user owns the upstream subscription;
    // nothing on our side expires). We only sweep the create-lock map so
    // it can't grow unbounded over the controller's lifetime.
    if let Some(gcp_watch) = services.gcp_watch_service.clone() {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                gcp_watch.cleanup_create_locks();
            }
        });
    }

    // ---------- Start Google Calendar channel renewal task ----------
    if google_calendar_service.is_configured() {
        let renewal_service = google_calendar_service.clone();
        let gcal_renewal_shutdown = bg_shutdown_rx.clone();
        tokio::spawn(async move {
            google_calendar::scheduler::channel_renewal_task(
                renewal_service,
                gcal_renewal_shutdown,
            )
            .await;
        });
        tracing::info!("Google Calendar channel renewal task started (runs every hour)");

        // Per-channel webhook rate-limiter cleanup (runs every 5 minutes).
        // Also sweeps the create_channel_locks DashMap to prevent
        // unbounded growth over the controller's lifetime.
        let cleanup_gcal_rl = google_calendar_service.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                cleanup_gcal_rl.cleanup_webhook_channel_limits();
                cleanup_gcal_rl.cleanup_create_channel_locks();
            }
        });

        // Event sync task will be started after Redis/NATS are initialized
    }

    // ---------- Start OAuth proactive token refresh task ----------
    {
        let cred_service_bg = oauth_credential_service.clone();
        tokio::spawn(async move {
            oauth::refresh_task::proactive_token_refresh_task(cred_service_bg).await;
        });
        tracing::info!("OAuth proactive token refresh task started (5-minute interval)");
    }
}

/// WASM-log subscriber + job-result subscriber (both supervisor-wrapped,
/// MCP-1121/1122). Extracted verbatim from `main()`; spawn order preserved.
pub(crate) fn spawn_nats_log_subscribers(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    nats_client: Option<std::sync::Arc<async_nats::Client>>,
    services: &PlatformServices,
    buses: &EventBuses,
) -> anyhow::Result<()> {
    let module_execution_service = services.module_execution_service.clone();
    let worker_shared_key = services.worker_shared_key.clone();
    let tx = buses.tx.clone();
    let workflow_execution_tx = buses.workflow_execution_tx.clone();
    // ---------- Start WASM log subscriber (automatic logging from worker) ----------
    // This background task receives logs from WASM executions and persists them to database
    // Provides guaranteed observability for all WASM module executions
    if let Some(nats) = nats_client.clone() {
        let exec_service_for_logs = module_execution_service.clone();
        let tx_for_wasm_logs = tx.clone();
        // Build a lightweight ExecutionRepository for the wasm-log subscriber
        // so it can persist workflow-execution logs to the new
        // workflow_execution_logs table. Output encryption isn't needed —
        // the subscriber only writes logs, never reads encrypted outputs.
        let exec_repo_for_wasm_logs = std::sync::Arc::new(
            crate::execution_repository::ExecutionRepository::new(db_pool.clone())
                .with_workflow_execution_sender(workflow_execution_tx.clone()),
        );
        tokio::spawn(async move {
            tracing::info!("Starting WASM log subscriber on topic: wasm.log.*");

            // MCP-1121 (2026-05-16): supervisor loop wraps the inner
            // subscriber. Sibling sweep of MCP-1119/1120 (audit-ledger
            // JetStream + worker-fleet heartbeats). Pre-fix when
            // `subscriber.next()` returned None (NATS disconnect,
            // server-side unsubscribe, client reconnect window), the
            // spawned task exited and workflow execution logs stopped
            // persisting until controller restart — `workflow_execution_logs`
            // table received nothing, the UI's live log stream went
            // silent, and operators couldn't see workflow progress
            // mid-execution. Workers continue publishing to NATS but
            // without a JetStream durable here the messages drop on
            // the floor.
            //
            // Same audit rule (MCP-1119/1120): every background-spawned
            // message-consumer that processes external infrastructure
            // events MUST be supervisor-wrapped. Exponential backoff
            // caps at 60s, resets on successful bind.
            let mut backoff_secs: u64 = 1;
            'supervisor: loop {
                // Subscribe to all WASM log topics (wasm.log.{execution_id})
                let mut subscriber = match nats.subscribe("wasm.log.*").await {
                    Ok(sub) => sub,
                    Err(e) => {
                        tracing::error!(
                            target: "talos_controller",
                            event_kind = "wasm_log_subscribe_failed",
                            error = %e,
                            backoff_secs,
                            "Failed to subscribe to WASM logs; retrying after backoff"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(60);
                        continue 'supervisor;
                    }
                };
                backoff_secs = 1;

                tracing::info!("WASM log subscriber active - waiting for messages");

                // Process messages as they arrive
                while let Some(msg) = subscriber.next().await {
                    // DEBUG: Log when message is received
                    tracing::info!("📩 Received WASM log from NATS topic: {}", msg.subject);

                    // Parse log message from NATS
                    match serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                        Ok(log_msg) => {
                            // Extract fields with defaults
                            let execution_id = log_msg
                                .get("execution_id")
                                .and_then(|v| v.as_str())
                                .and_then(|s| uuid::Uuid::parse_str(s).ok());

                            let level_str = log_msg
                                .get("level")
                                .and_then(|v| v.as_str())
                                .unwrap_or("info");

                            // Convert string to LogLevel enum. Case-insensitive
                            // because the worker emits UPPERCASE ("INFO", "WARN",
                            // ...) while older test paths used lowercase. Without
                            // the fold, every uppercase line collapsed to Info.
                            let level = match level_str.to_ascii_lowercase().as_str() {
                                "debug" => LogLevel::Debug,
                                "warn" => LogLevel::Warn,
                                "error" => LogLevel::Error,
                                _ => LogLevel::Info,
                            };

                            let message = log_msg
                                .get("message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();

                            let metadata = log_msg.get("metadata").cloned();
                            let trace_id = log_msg
                                .get("trace_id")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            let span_id = log_msg
                                .get("span_id")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());

                            // Save to database (best-effort - don't crash on error)
                            if let Some(exec_id) = execution_id {
                                let node_id = metadata
                                    .as_ref()
                                    .and_then(|m| m.get("node_id"))
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| uuid::Uuid::parse_str(s).ok());

                                // MCP-1011 sibling: scrub the broadcast `message`
                                // the same way `add_workflow_log` scrubs before
                                // persisting. Pre-fix the persistence path
                                // (`workflow_execution_logs.message`) applied
                                // MCP-481 truncation + control-char strip +
                                // `redact_str`, but the parallel `tx_for_wasm_logs`
                                // broadcast used the raw `message` — a WASM module
                                // emitting a Bearer / sk- / ghp_ token leaked it
                                // to live `execution_updates` GraphQL subscribers
                                // even though the persisted row was clean. See
                                // `scrub_wasm_log_for_broadcast` (above) for the
                                // canonical pipeline — kept in lockstep with the
                                // persistence path so the live channel can't
                                // carry more than the persisted row.
                                let scrubbed_for_broadcast = scrub_wasm_log_for_broadcast(&message);

                                // Broadcast the live log to all connected GraphQL clients!
                                let _ = tx_for_wasm_logs.send(ExecutionEvent {
                                    execution_id: exec_id,
                                    node_id,
                                    status: ExecutionStatus::Running,
                                    trace_id,
                                    span_id,
                                    log_message: Some(format!(
                                        "[{}] {}",
                                        level_str.to_uppercase(),
                                        scrubbed_for_broadcast
                                    )),
                                    iteration_index: None,
                                    iteration_total: None,
                                    duration_ms: None,
                                    output: None,
                                });

                                // Route to the right log table:
                                //   - workflow_execution_logs when exec_id is a workflow_executions.id
                                //     (the common case — every run via trigger_workflow / call_workflow / scheduled)
                                //   - module_execution_logs when exec_id is a module_executions.id
                                //     (standalone module runs via webhook / test_module)
                                // `add_workflow_log` does a `WHERE EXISTS`-guarded insert and
                                // returns `Ok(false)` (rather than tripping the FK constraint)
                                // when exec_id isn't a workflow execution — so the standalone-
                                // module case no longer emits a Postgres FK-violation ERROR per
                                // log line. Single round trip for the common (workflow) case.
                                let level_upper = match level {
                                    LogLevel::Debug => "DEBUG",
                                    LogLevel::Info => "INFO",
                                    LogLevel::Warn => "WARN",
                                    LogLevel::Error => "ERROR",
                                };
                                match exec_repo_for_wasm_logs
                                    .add_workflow_log(
                                        exec_id,
                                        node_id,
                                        level_upper,
                                        &message,
                                        metadata.as_ref(),
                                    )
                                    .await
                                {
                                    Ok(true) => {} // landed in workflow_execution_logs
                                    Ok(false) => {
                                        // Not a workflow execution → standalone module run.
                                        exec_service_for_logs
                                            .add_log_best_effort(exec_id, level, message, metadata)
                                            .await;
                                    }
                                    Err(e) => {
                                        // exec_id IS a workflow execution but the insert failed
                                        // (5000-entry rate-limit trigger, DB outage). Don't
                                        // misroute a real workflow log to the module table.
                                        tracing::debug!(
                                            %exec_id,
                                            error = %e,
                                            "workflow_execution_logs insert failed (capped or DB error)"
                                        );
                                    }
                                }
                            } else {
                                tracing::debug!("Received WASM log without valid execution_id");
                            }
                        }
                        Err(e) => {
                            tracing::debug!("Failed to parse WASM log message: {}", e);
                        }
                    }
                }

                // MCP-1121: stream ended — supervisor re-binds.
                tracing::warn!(
                    target: "talos_controller",
                    event_kind = "wasm_log_subscriber_rebinding",
                    "WASM log subscriber stream ended; supervisor re-binding (no controller restart required)"
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            } // end 'supervisor
        });
        tracing::info!("WASM log subscriber task started");

        // ---------- Start job result subscriber ----------
        // The worker publishes JobResult messages to talos.results.{job_id} after each
        // WASM execution completes.  This subscriber receives those results and updates
        // the module_executions record status to 'completed' or 'failed' so the UI can
        // display the outcome.
        let exec_service_for_results = module_execution_service.clone();
        let nats_for_results = nats_client
            .clone()
            .ok_or_else(|| anyhow::anyhow!("NATS client missing"))?;
        // Clone the shared key into a verify-ring (current + any staged
        // WORKER_SHARED_KEY_PREVIOUS) so this audit observer accepts results
        // signed under a previous key during a rolling rotation, consistent
        // with the primary verifier in the engine dispatcher. Moved into the
        // spawn; the original `worker_shared_key` is still used later for the
        // Extension layer.
        let worker_key_ring_for_results = worker_shared_key.clone().map(|signing| {
            talos_workflow_engine_core::WorkerKeyRing::new(
                signing,
                talos_workflow_job_protocol::load_worker_shared_key_previous().unwrap_or_default(),
            )
        });
        tokio::spawn(async move {
            tracing::info!("Starting job result subscriber on topic: talos.results.*");

            // MCP-1122 (2026-05-16): supervisor loop wraps the inner
            // subscriber. Fourth site in the MCP-1119/1120/1121 sweep.
            // The comment further down at line ~2960 notes this
            // subscriber is "mostly dormant" today (every NATS-dispatched
            // path uses request-reply), but it's the canonical landing
            // point for future async-dispatch / work-queue patterns —
            // when those land, the subscriber silently exiting on
            // stream-end (NATS reconnect, server-side unsubscribe,
            // client reconnect window) would be a latent reliability
            // gap. Bring it into supervisor parity with siblings now
            // so a future regression doesn't surface as "results
            // mysteriously stopped updating after a NATS hiccup."
            let mut backoff_secs: u64 = 1;
            'supervisor: loop {
                let mut sub = match nats_for_results.subscribe("talos.results.*").await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(
                            target: "talos_controller",
                            event_kind = "job_result_subscribe_failed",
                            error = %e,
                            backoff_secs,
                            "Failed to subscribe to job results; retrying after backoff"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(60);
                        continue 'supervisor;
                    }
                };
                backoff_secs = 1;

                tracing::info!("Job result subscriber active");

                while let Some(msg) = sub.next().await {
                    match serde_json::from_slice::<talos_workflow_job_protocol::JobResult>(
                        &msg.payload,
                    ) {
                        Ok(result) => {
                            let job_id = result.job_id;

                            // SECURITY: Verify HMAC-SHA256 signature + freshness
                            // window. Rejects results injected by any process that
                            // can publish to NATS but does not know the pre-shared
                            // key.
                            //
                            // Post-r301 the worker single-publishes: it sends a
                            // result to EITHER the request-reply inbox OR
                            // `talos.results.{job_id}` based on whether the
                            // requester awaited the reply, never both. So this
                            // subscriber only sees results that no other in-process
                            // verifier has handled — there's no second verify to
                            // race.
                            //
                            // We still call `verify_no_replay` here (not `verify`)
                            // as defense-in-depth: it keeps this subscriber
                            // safe-by-default if a future code path re-introduces a
                            // dual-publish or a sibling subscriber, and the side
                            // effect (`UPDATE module_executions WHERE status IN
                            // ('pending','running')`) is idempotent under replay
                            // anyway. HMAC + freshness still catch forgery and
                            // stale-replay; the worker is the primary
                            // replay-cache writer for fire-and-forget results.
                            //
                            // Today every NATS-dispatched code path uses
                            // request-reply, so this subscriber is mostly dormant
                            // — kept as the canonical landing point for future
                            // truly-async dispatches (work-queue style).
                            // L-4: typed Observer verifier — this audit
                            // subscriber on `talos.results.*` only writes
                            // an idempotent UPDATE; primary verification
                            // happens at the request-reply inbox in the
                            // engine dispatcher / webhook handler. Using
                            // `Verifier::Observer` documents the role at
                            // the type level so a future refactor can't
                            // accidentally convert this site to a primary
                            // verifier and reintroduce the r300 regression.
                            if let Some(ref ring) = worker_key_ring_for_results {
                                // RFC 0010 P2: scheme-routing Observer verify —
                                // Ed25519 against the keys registered for this
                                // worker_id, or legacy HMAC against the ring
                                // while `result_accept_legacy_hmac()`. NEVER
                                // records the replay cache (Observer role): the
                                // request-reply dispatcher is the sole Primary
                                // verifier, per the verify-once rule.
                                let worker_ed_keys =
                                    talos_workflow_job_protocol::worker_public_keys(
                                        &result.worker_id,
                                    );
                                if let Err(e) = result.verify_no_replay_dispatch(
                                    ring,
                                    &worker_ed_keys,
                                    300,
                                    talos_workflow_job_protocol::result_accept_legacy_hmac(),
                                ) {
                                    tracing::warn!(
                                    "Rejected job result {}: signature verification failed — {}",
                                    job_id,
                                    e
                                );
                                    continue;
                                }
                            }
                            tracing::debug!(
                                "📥 Received job result: {} ({:?}, {}ms)",
                                job_id,
                                result.status,
                                result.execution_time_ms
                            );

                            match result.status {
                                talos_workflow_job_protocol::JobStatus::Success => {
                                    if let Err(e) = exec_service_for_results
                                        .complete_execution_from_worker(
                                            job_id,
                                            Some(result.output_payload),
                                        )
                                        .await
                                    {
                                        tracing::warn!(
                                            "Failed to mark execution {} as completed: {}",
                                            job_id,
                                            e
                                        );
                                    } else {
                                        tracing::info!(
                                            "✅ Execution {} completed ({}ms)",
                                            job_id,
                                            result.execution_time_ms
                                        );
                                    }
                                }
                                talos_workflow_job_protocol::JobStatus::Failed
                                | talos_workflow_job_protocol::JobStatus::TimedOut => {
                                    let error_msg = result
                                        .output_payload
                                        .get("error")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("Worker reported failure")
                                        .to_string();
                                    let error_type = matches!(
                                        result.status,
                                        talos_workflow_job_protocol::JobStatus::TimedOut
                                    )
                                    .then_some("timeout".to_string());

                                    if let Err(e) = exec_service_for_results
                                        .fail_execution_from_worker(
                                            job_id,
                                            error_msg.clone(),
                                            error_type,
                                        )
                                        .await
                                    {
                                        tracing::warn!(
                                            "Failed to mark execution {} as failed: {}",
                                            job_id,
                                            e
                                        );
                                    } else {
                                        // MCP-989 (2026-05-15): DLP-redact the
                                        // failure preview at the operator-log
                                        // boundary. `fail_execution_from_worker`
                                        // redacts before persisting to
                                        // `module_executions.error_message`
                                        // (MCP-968), but this INFO log was
                                        // taking the first 100 chars of the
                                        // ORIGINAL worker-supplied error_msg.
                                        // Worker failures regularly carry
                                        // upstream auth errors that echo the
                                        // rejected token in the body; secret-
                                        // shaped prefixes must not land in
                                        // operator log pipelines. Same
                                        // wrapper class as the two
                                        // talos-module-executions sites
                                        // closed in this MCP.
                                        let preview: String =
                                            talos_dlp_provider::redact_str(&error_msg)
                                                .chars()
                                                .take(100)
                                                .collect();
                                        tracing::info!(
                                            "❌ Execution {} failed: {}",
                                            job_id,
                                            preview
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!("Failed to parse job result message: {}", e);
                        }
                    }
                }

                // MCP-1122: stream ended — supervisor re-binds.
                tracing::warn!(
                    target: "talos_controller",
                    event_kind = "job_result_subscriber_rebinding",
                    "Job result subscriber stream ended; supervisor re-binding"
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            } // end 'supervisor
        });
        tracing::info!("Job result subscriber task started");
    } else {
        tracing::warn!("NATS not configured - WASM automatic logging disabled");
    }

    // Note: Periodic event sync task removed — sync_channel_events() advances the sync
    // token each time it runs, which would silently consume the token before the webhook
    // handler could use it, causing missed events. Syncing is driven exclusively by
    // real-time push notifications (webhook_notification_handler).

    Ok(())
}

/// Stale-execution cleanup, the workflow scheduler, and the SLA threshold
/// breach check. Extracted verbatim from `main()`; spawn order preserved
/// (these three started after router assembly in the original body).
pub(crate) fn spawn_late_background_tasks(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    nats_client: Option<std::sync::Arc<async_nats::Client>>,
    core: &CoreServices,
    services: &PlatformServices,
    tx_for_scheduler: broadcast::Sender<ExecutionEvent>,
    bg_shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let secrets_manager = core.secrets_manager.clone();
    let registry = core.registry.clone();
    let worker_manager = services.worker_manager.clone();
    let module_execution_service = services.module_execution_service.clone();
    let worker_shared_key = services.worker_shared_key.clone();
    // ---------- Start stale execution cleanup task ----------
    // Marks executions stuck in 'running' state beyond a configurable threshold
    // as 'failed'. Prevents ghost executions from accumulating indefinitely.
    //
    // MCP-1042 (2026-05-15): subscribe to `bg_shutdown_rx` so SIGTERM
    // exits the loop cleanly between ticks instead of aborting the
    // task (and any in-flight UPDATE) when the tokio runtime drops at
    // process end. Sibling discipline to the LLM-keys cache sweep
    // (line 1075) and the actor-memory TTL sweep — DB-writing
    // background loops need explicit shutdown wiring to avoid
    // wedging a connection-pool entry on a half-issued statement.
    let cleanup_pool = db_pool.clone();
    let cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = cleanup_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // MCP-665 (2026-05-13): route through `positive_env_or_default`
                    // so `STALE_EXECUTION_MINUTES=0` doesn't mass-fail every
                    // in-flight execution on the next tick. With `=0`,
                    // `make_interval(mins => 0)` is zero, so
                    // `started_at < NOW() - 0` matches every running row →
                    // catastrophic auto-cleanup that terminates every workflow.
                    // Negative values are equally destructive (NOW() - negative =
                    // future time, also matches everything). Same `=0` footgun
                    // class as MCP-638/643/661/663/664 — this one's the highest-
                    // blast-radius of the set (mass execution kill).
                    let stale_minutes: i32 =
                        talos_config::positive_env_or_default("STALE_EXECUTION_MINUTES", 60i32);
                    let result = sqlx::query(
                        "UPDATE workflow_executions SET status = 'failed', \
                         error_message = 'Auto-cleaned: execution stale (running > configured threshold)', \
                         completed_at = NOW() \
                         WHERE status IN ('running') AND status != 'queued' AND started_at < NOW() - make_interval(mins => $1::int)"
                    ).bind(stale_minutes).execute(&cleanup_pool).await;
                    if let Ok(r) = result {
                        if r.rows_affected() > 0 {
                            tracing::info!(count = r.rows_affected(), "Auto-cleaned stale executions");
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Stale execution cleanup loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("Stale execution auto-cleanup task started (runs every 5 minutes, threshold configurable via STALE_EXECUTION_MINUTES)");

    // ---------- Start workflow scheduler ----------
    // Polls every 15 seconds for due schedules and triggers workflow executions.
    // Requires NATS (already required by WebhookRouter, so always available if server started).
    if let Some(nats) = nats_client.clone() {
        let scheduler = std::sync::Arc::new(crate::scheduler::SchedulerService::new(
            db_pool.clone(),
            tx_for_scheduler,
            registry.clone(),
            secrets_manager.clone(),
            worker_manager.clone(),
            module_execution_service.clone(),
            worker_shared_key.clone(),
            nats,
        ));
        let scheduler_shutdown = bg_shutdown_rx.clone();
        tokio::spawn(async move {
            scheduler.run_with_shutdown(scheduler_shutdown).await;
        });
        tracing::info!("Workflow scheduler started (polls every 15 seconds, backfills null next_trigger_at on startup; graceful-shutdown enabled)");
    } else {
        tracing::warn!(
            "Workflow scheduler not started: NATS_URL not configured. \
             Scheduled workflows will not fire automatically."
        );
    }

    // ---------- Start SLA threshold breach check task (Round 43) ----------
    // MCP-1045: subscribe to bg_shutdown_rx — issues per-threshold
    // INSERTs into workflow_sla_alerts on breach detection. Outer
    // 5-min ticker gated; inner per-threshold INSERT runs to natural
    // completion within one tick.
    let sla_pool = db_pool.clone();
    let sla_breach_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = sla_breach_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Every 5 min
                                                                                       // MCP-497: same SSRF-via-redirect fix as MCP-469/470 — the
                                                                                       // `check_outbound_url_no_ssrf` gate below catches the literal
                                                                                       // URL but a 302 from the validated host to an internal host
                                                                                       // bypasses it if reqwest's default redirect policy is in
                                                                                       // effect. `Client::default()` (the prior fallback) re-enables
                                                                                       // following up to 10 hops, so a build-time TLS failure here
                                                                                       // silently reopened the SSRF gap. `.expect()` makes the
                                                                                       // failure loud at startup; `.redirect(Policy::none())` makes
                                                                                       // the SSRF re-check load-bearing.
                                                                                       // MCP-1034: explicit connect_timeout — fast-fail on black-holed
                                                                                       // SLA-alert endpoint.
                                                                                       // Built via the shared SSRF-safe builder (redirect(none) + connect-time
                                                                                       // ControllerSsrfResolver) — same user-supplied SLA-webhook + DNS-rebinding
                                                                                       // rationale as the sibling SLA-monitor client above (PR #162).
        let client =
            talos_http_utils::outbound::build_outbound_webhook_client("talos-sla-webhook/1.0")
                .expect("SLA monitor: failed to build hardened reqwest client");
        loop {
            let should_proceed = tokio::select! {
                _ = interval.tick() => true,
                _ = shutdown.changed() => !*shutdown.borrow(),
            };
            if !should_proceed {
                tracing::info!("SLA threshold breach loop received shutdown signal");
                break;
            }

            // Load all thresholds with their workflow's user_id for scoped queries
            let thresholds = sqlx::query(
                "SELECT t.workflow_id, t.user_id, t.p95_latency_ms, \
                        t.success_rate_pct::float8 AS success_rate_pct, \
                        t.notification_webhook \
                 FROM workflow_sla_thresholds t",
            )
            .fetch_all(&sla_pool)
            .await;

            let thresholds = match thresholds {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!("SLA threshold check: failed to load thresholds: {}", e);
                    continue;
                }
            };

            for row in &thresholds {
                use sqlx::Row;
                let workflow_id: uuid::Uuid = row.get("workflow_id");
                let user_id: uuid::Uuid = row.get("user_id");
                let p95_threshold: Option<i64> = row.get("p95_latency_ms");
                let success_threshold: Option<f64> = row.get("success_rate_pct");
                let webhook: String = row.get("notification_webhook");

                // Re-validate at fire time. Stored URLs that predate the
                // r285 SSRF hardening (obfuscated IPv4 — octal/hex/integer
                // encodings) were accepted at write time but resolve to
                // internal IPs at fire time. Skip rather than fire.
                if let Err(reason) = crate::mcp::utils::check_outbound_url_no_ssrf(&webhook) {
                    tracing::warn!(
                        workflow_id = %workflow_id,
                        "SLA monitor: skipping fire — stored webhook fails SSRF re-check: {reason}"
                    );
                    continue;
                }

                // Query last-24h stats
                let stats = sqlx::query(
                    "SELECT \
                        COUNT(*) FILTER (WHERE status = 'completed')::bigint AS succeeded, \
                        COUNT(*)::bigint AS total, \
                        PERCENTILE_CONT(0.95) WITHIN GROUP \
                            (ORDER BY EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000) \
                            AS p95_ms \
                     FROM workflow_executions \
                     WHERE workflow_id = $1 AND user_id = $2 \
                       AND started_at > NOW() - INTERVAL '24 hours' \
                       AND completed_at IS NOT NULL",
                )
                .bind(workflow_id)
                .bind(user_id)
                .fetch_one(&sla_pool)
                .await;

                let stats = match stats {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let total: i64 = stats.get("total");
                if total == 0 {
                    continue;
                }
                let succeeded: i64 = stats.get("succeeded");
                let p95_ms: Option<f64> = stats.get("p95_ms");
                let actual_success_pct = (succeeded as f64 / total as f64) * 100.0;

                let now = chrono::Utc::now().to_rfc3339();

                // Check p95 latency breach
                if let (Some(threshold), Some(actual)) = (p95_threshold, p95_ms) {
                    if actual > threshold as f64 {
                        let payload = serde_json::json!({
                            "event": "sla_breach",
                            "workflow_id": workflow_id,
                            "metric": "p95_latency_ms",
                            "threshold": threshold,
                            "actual": actual as i64,
                            "timestamp": now,
                        });
                        tracing::warn!(
                            workflow_id = %workflow_id,
                            threshold = threshold,
                            actual = actual as i64,
                            "SLA breach: p95 latency exceeded"
                        );
                        let client = client.clone();
                        let webhook = webhook.clone();
                        // MCP-809 (2026-05-14): canonical 3-arm match.
                        // Pre-fix this fire only logged on Err — an
                        // operator-supplied webhook returning 4xx/5xx
                        // (e.g. PagerDuty rate-limited / Slack 503 /
                        // OpsGenie 502) was silently treated as
                        // success. The sibling 15-min SLA-degradation
                        // fire at ~line 2209 already follows the canonical
                        // shape (MCP-774); this 5-min SLA-breach task
                        // had drifted. Same misleading-success class as
                        // MCP-737/738/800/801. WARN+target talos_rpc so
                        // dashboards correlate delivery-failure rate
                        // with controller health.
                        tokio::spawn(async move {
                            match client.post(&webhook).json(&payload).send().await {
                                Ok(resp) if resp.status().is_success() => {
                                    tracing::debug!(
                                        webhook = %webhook,
                                        status = resp.status().as_u16(),
                                        "SLA-breach (p95) webhook delivered"
                                    );
                                }
                                Ok(resp) => {
                                    tracing::warn!(
                                        target: "talos_rpc",
                                        webhook = %webhook,
                                        status = resp.status().as_u16(),
                                        "SLA-breach (p95) webhook returned non-success status — operator notification may not have reached its destination"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        target: "talos_rpc",
                                        webhook = %webhook,
                                        error = %e,
                                        "SLA-breach (p95) webhook POST failed — operator notification undelivered"
                                    );
                                }
                            }
                        });
                    }
                }

                // Check success rate breach
                if let Some(threshold) = success_threshold {
                    if actual_success_pct < threshold {
                        let payload = serde_json::json!({
                            "event": "sla_breach",
                            "workflow_id": workflow_id,
                            "metric": "success_rate_pct",
                            "threshold": threshold,
                            "actual": (actual_success_pct * 100.0).round() / 100.0,
                            "timestamp": now,
                        });
                        tracing::warn!(
                            workflow_id = %workflow_id,
                            threshold = threshold,
                            actual = actual_success_pct,
                            "SLA breach: success rate below threshold"
                        );
                        let client = client.clone();
                        let webhook = webhook.clone();
                        // MCP-809 (2026-05-14): same misleading-success drift
                        // as the p95 sibling above; mirror the canonical
                        // 3-arm match. See p95 comment for rationale.
                        tokio::spawn(async move {
                            match client.post(&webhook).json(&payload).send().await {
                                Ok(resp) if resp.status().is_success() => {
                                    tracing::debug!(
                                        webhook = %webhook,
                                        status = resp.status().as_u16(),
                                        "SLA-breach (success-rate) webhook delivered"
                                    );
                                }
                                Ok(resp) => {
                                    tracing::warn!(
                                        target: "talos_rpc",
                                        webhook = %webhook,
                                        status = resp.status().as_u16(),
                                        "SLA-breach (success-rate) webhook returned non-success status — operator notification may not have reached its destination"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        target: "talos_rpc",
                                        webhook = %webhook,
                                        error = %e,
                                        "SLA-breach (success-rate) webhook POST failed — operator notification undelivered"
                                    );
                                }
                            }
                        });
                    }
                }
            }
        }
    });
    tracing::info!("SLA threshold breach check task started (runs every 5 minutes)");
}

#[cfg(test)]
mod scrub_wasm_log_for_broadcast_tests {
    use super::{scrub_wasm_log_for_broadcast, MAX_BROADCAST_LOG_CHARS};

    #[test]
    fn redacts_anthropic_secret() {
        // MCP-1011 sibling: a WASM module emitting `sk-ant-...` must
        // have it redacted BEFORE the broadcast lands on the live
        // `execution_updates` channel. The persistence path
        // (`add_workflow_log`) applied this; the broadcast didn't.
        let raw = "thinking response sk-ant-abcdefghijklmnopqrstuvwxyz0123456789 returned";
        let out = scrub_wasm_log_for_broadcast(raw);
        assert!(
            !out.contains("sk-ant-abcdefghijklmnopqrstuvwxyz0123456789"),
            "DLP scrubber must remove the secret. Got: {out}"
        );
    }

    #[test]
    fn redacts_bearer_token() {
        let raw = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig";
        let out = scrub_wasm_log_for_broadcast(raw);
        assert!(
            !out.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"),
            "Bearer JWT must be redacted. Got: {out}"
        );
    }

    #[test]
    fn redacts_github_token() {
        let raw = "git push uses ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // secret-scan-allow: DLP redaction test fixture
        let out = scrub_wasm_log_for_broadcast(raw);
        assert!(
            !out.contains("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), // secret-scan-allow: DLP redaction test fixture
            "GitHub PAT must be redacted. Got: {out}"
        );
    }

    #[test]
    fn strips_control_chars_except_whitespace() {
        // ANSI escape sequences and other control chars must not
        // reach operator dashboards (terminal-render attacks). \n,
        // \t, \r preserved so multi-line logs format correctly.
        let raw = "before\x1b[31mafter\nnext\ttabbed\rret\x07bell";
        let out = scrub_wasm_log_for_broadcast(raw);
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\x07'));
        assert!(out.contains('\n'));
        assert!(out.contains('\t'));
        assert!(out.contains('\r'));
    }

    #[test]
    fn truncates_oversize_input() {
        // Char-based truncation must respect the 8 KiB cap so the
        // broadcast can't carry more than `add_workflow_log` persists.
        let raw: String = "a".repeat(MAX_BROADCAST_LOG_CHARS + 1000);
        let out = scrub_wasm_log_for_broadcast(&raw);
        assert!(out.contains("... (truncated)"));
        // After truncation the prefix is exactly MAX chars, then the
        // marker; total chars <= cap + marker length.
        assert!(out.chars().count() <= MAX_BROADCAST_LOG_CHARS + "... (truncated)".chars().count());
    }

    #[test]
    fn small_input_passes_through_clean() {
        let raw = "user logged in successfully";
        let out = scrub_wasm_log_for_broadcast(raw);
        assert_eq!(out, raw);
    }
}
