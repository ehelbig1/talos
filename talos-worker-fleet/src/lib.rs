use dashmap::DashMap;
use futures::StreamExt;
use std::sync::Arc;
use talos_workflow_job_protocol::WorkerHeartbeat;
use tokio::time::{Duration, Instant};
use uuid::Uuid;

/// Tracks the state of a single worker in the fleet.
#[derive(Debug, Clone)]
pub struct WorkerState {
    pub heartbeat: WorkerHeartbeat,
    pub last_seen: Instant,
}

/// Manages the registry of active workers, processing heartbeats and pruning stale entries.
pub struct WorkerManager {
    /// Thread-safe map of worker IDs to their last known state.
    workers: DashMap<Uuid, WorkerState>,
    /// The shared key used to verify HMAC signatures on heartbeats.
    shared_key: Vec<u8>,
}

impl WorkerManager {
    /// Creates a new WorkerManager with the given shared secret key.
    pub fn new(shared_key: Vec<u8>) -> Self {
        Self {
            workers: DashMap::new(),
            shared_key,
        }
    }

    /// Processes an incoming heartbeat, verifying its signature and updating the registry.
    pub fn handle_heartbeat(&self, hb: WorkerHeartbeat) -> anyhow::Result<()> {
        // 1. Verify the signature and nonce to prevent tampering and replays.
        if let Err(e) = hb.verify(&self.shared_key, 60) {
            return Err(anyhow::anyhow!(
                "Invalid heartbeat signature from worker {}: {}",
                hb.worker_id,
                e
            ));
        }

        // 2. Update the registry with the latest metrics and timestamp.
        self.workers.insert(
            hb.worker_id,
            WorkerState {
                heartbeat: hb,
                last_seen: Instant::now(),
            },
        );

        Ok(())
    }

    /// Returns a list of all currently active workers.
    pub fn get_active_workers(&self) -> Vec<WorkerHeartbeat> {
        self.workers
            .iter()
            .map(|kv| kv.value().heartbeat.clone())
            .collect()
    }

    /// Returns a list of workers that possess a specific capability.
    pub fn get_workers_with_capability(&self, capability: &str) -> Vec<WorkerHeartbeat> {
        self.workers
            .iter()
            .filter(|kv| {
                kv.value()
                    .heartbeat
                    .capabilities
                    .contains(&capability.to_string())
            })
            .map(|kv| kv.value().heartbeat.clone())
            .collect()
    }

    /// Finds the "best" worker that satisfies all required capabilities.
    /// Returns None if no suitable worker is found.
    /// Currently uses a simple heuristic: lowest CPU usage.
    pub fn find_best_worker(&self, required_caps: &[String]) -> Option<WorkerHeartbeat> {
        self.workers
            .iter()
            .filter(|kv| {
                let worker_caps = &kv.value().heartbeat.capabilities;
                // Check if worker has ALL required capabilities.
                required_caps.iter().all(|req| worker_caps.contains(req))
            })
            .min_by(|a, b| {
                // Heuristic: Pick the one with the lowest CPU usage.
                let cpu_a = a.value().heartbeat.cpu_usage_pct;
                let cpu_b = b.value().heartbeat.cpu_usage_pct;
                cpu_a
                    .partial_cmp(&cpu_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|kv| kv.value().heartbeat.clone())
    }

    /// Returns the number of currently registered workers.
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Returns the fleet utilization as a fraction (0.0 – 1.0).
    ///
    /// Utilization is defined as the proportion of workers whose CPU usage
    /// exceeds the `busy_threshold_pct`.  Returns 0.0 when the fleet is empty.
    pub fn fleet_utilization(&self, busy_threshold_pct: f32) -> f64 {
        let total = self.workers.len();
        if total == 0 {
            return 0.0;
        }
        let busy = self
            .workers
            .iter()
            .filter(|kv| kv.value().heartbeat.cpu_usage_pct > busy_threshold_pct)
            .count();
        busy as f64 / total as f64
    }

    /// Returns `true` if the fleet is saturated (all workers above threshold).
    /// Useful for backpressure decisions.
    pub fn is_fleet_saturated(&self, busy_threshold_pct: f32) -> bool {
        if self.workers.is_empty() {
            return true; // No workers available at all.
        }
        self.workers
            .iter()
            .all(|kv| kv.value().heartbeat.cpu_usage_pct > busy_threshold_pct)
    }

    /// Removes workers that haven't sent a heartbeat within the specified duration.
    pub fn prune_stale(&self, max_age: Duration) {
        let now = Instant::now();
        let initial_count = self.workers.len();
        self.workers.retain(|_, state| {
            if now.duration_since(state.last_seen) >= max_age {
                tracing::info!("Pruning stale worker: {}", state.heartbeat.worker_id);
                false
            } else {
                true
            }
        });

        let pruned = initial_count - self.workers.len();
        if pruned > 0 {
            tracing::info!("Pruned {} stale workers from fleet", pruned);
        }
    }
}

/// Spawns the background tasks for heartbeat subscription and stale worker pruning.
pub async fn start_worker_management(
    manager: Arc<WorkerManager>,
    nats: async_nats::Client,
) -> anyhow::Result<()> {
    // 1. Subscribe to all worker heartbeats.
    // Workers publish to talos.workers.heartbeat.<worker_id>
    //
    // MCP-1120 (2026-05-16): supervisor loop re-binds the subscription
    // on stream-end. Sibling of MCP-1119 (audit-ledger JetStream
    // supervisor). Pre-fix the spawned task exited when
    // `subscriber.next()` returned None (NATS disconnect, subscription
    // dropped server-side, client reconnect window) → no new
    // heartbeats observed → the prune task at line ~181 still ran
    // → every worker appeared stale within `prune_stale` window
    // (60s) → worker manager thought the entire fleet was down →
    // orchestration broke until controller restart.
    //
    // The async-nats Client handles connection-level reconnects
    // transparently, but the per-subject Subscription is a separate
    // logical handle that can end (server-side unsubscribe, client
    // re-init). The supervisor re-binds on that boundary.
    let manager_hb = manager.clone();
    let nats_hb = nats.clone();
    tokio::spawn(async move {
        tracing::info!("Worker heartbeat listener started");
        let mut backoff_secs: u64 = 1;
        loop {
            let mut subscriber = match nats_hb
                .subscribe(talos_workflow_job_protocol::subjects::WORKERS_HEARTBEAT_WILDCARD)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        target: "talos_worker_fleet",
                        event_kind = "heartbeat_subscribe_failed",
                        error = %e,
                        backoff_secs,
                        "Worker-fleet heartbeat subscribe failed; retrying after backoff"
                    );
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                    continue;
                }
            };
            backoff_secs = 1;
            while let Some(msg) = subscriber.next().await {
                match serde_json::from_slice::<WorkerHeartbeat>(&msg.payload) {
                    Ok(hb) => {
                        if let Err(e) = manager_hb.handle_heartbeat(hb) {
                            tracing::warn!("Heartbeat verification failed: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to deserialize worker heartbeat: {}", e);
                    }
                }
            }
            tracing::warn!(
                target: "talos_worker_fleet",
                event_kind = "heartbeat_subscriber_rebinding",
                "Worker heartbeat subscriber stream ended; supervisor re-binding"
            );
            // Don't tight-loop if NATS is wedged.
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    // 2. Periodic pruning task.
    let manager_prune = manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            // Prune workers that haven't checked in for 1 minute.
            manager_prune.prune_stale(Duration::from_secs(60));
        }
    });

    Ok(())
}
