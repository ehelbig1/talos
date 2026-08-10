//! `WorkerManager` behaviour over the NATS fleet heartbeat.
//!
//! `worker_id` is TEXT here, in the same key space as
//! `worker_identities.worker_id` and `JobResult.worker_id`. It was a `Uuid`
//! until 2026-08, which left the fleet view structurally unjoinable with the
//! identity registry — the mismatch that twice nearly produced a design
//! intersecting the registry against an (always empty) fleet map.

use controller::worker_manager::WorkerManager;
use std::time::Duration;
use talos_workflow_job_protocol::WorkerHeartbeat;

fn test_key() -> Vec<u8> {
    vec![0x42u8; 32]
}

fn create_heartbeat(id: &str, cpu: f32, caps: Vec<String>) -> WorkerHeartbeat {
    let mut hb = WorkerHeartbeat {
        worker_id: id.to_string(),
        capabilities: caps,
        cpu_usage_pct: cpu,
        build_version: Some("0.1.0+abc1234".to_string()),
        signature: vec![],
        heartbeat_nonce: String::new(),
    };
    hb.sign(&test_key()).unwrap();
    hb
}

#[tokio::test]
async fn test_handle_heartbeat() {
    let manager = WorkerManager::new(test_key());
    let id = "talos-worker-0";
    let hb = create_heartbeat(id, 10.0, vec!["wasm".to_string()]);

    manager
        .handle_heartbeat(hb.clone())
        .expect("Should handle valid heartbeat");

    let active = manager.get_active_workers();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].worker_id, id);
}

#[tokio::test]
async fn test_find_best_worker_cpu_heuristic() {
    let manager = WorkerManager::new(test_key());
    let id1 = "talos-worker-1";
    let id2 = "talos-worker-2";

    // Worker 1: 50% CPU
    let hb1 = create_heartbeat(id1, 50.0, vec!["wasm".to_string()]);
    // Worker 2: 10% CPU
    let hb2 = create_heartbeat(id2, 10.0, vec!["wasm".to_string()]);

    manager.handle_heartbeat(hb1).unwrap();
    manager.handle_heartbeat(hb2).unwrap();

    let best = manager
        .find_best_worker(&["wasm".to_string()])
        .expect("Should find a worker");
    assert_eq!(
        best.worker_id, id2,
        "Should pick worker with lowest CPU usage"
    );
}

#[tokio::test]
async fn test_find_best_worker_capability_filtering() {
    let manager = WorkerManager::new(test_key());
    let id1 = "talos-worker-1";
    let id2 = "talos-worker-2";

    // Worker 1: has 'gpu'
    let hb1 = create_heartbeat(id1, 10.0, vec!["gpu".to_string()]);
    // Worker 2: has 'wasm'
    let hb2 = create_heartbeat(id2, 5.0, vec!["wasm".to_string()]);

    manager.handle_heartbeat(hb1).unwrap();
    manager.handle_heartbeat(hb2).unwrap();

    let best = manager
        .find_best_worker(&["gpu".to_string()])
        .expect("Should find worker with gpu");
    assert_eq!(best.worker_id, id1);

    let none = manager.find_best_worker(&["nonexistent".to_string()]);
    assert!(none.is_none());
}

#[tokio::test]
async fn test_prune_stale_workers() {
    let manager = WorkerManager::new(test_key());
    let id = "talos-worker-0";
    let hb = create_heartbeat(id, 10.0, vec![]);

    manager.handle_heartbeat(hb).unwrap();
    assert_eq!(manager.get_active_workers().len(), 1);

    // Prune with 0s age (should prune everything)
    manager.prune_stale(Duration::from_secs(0));
    assert_eq!(manager.get_active_workers().len(), 0);
}

#[tokio::test]
async fn test_load_balancing_many_workers() {
    let manager = WorkerManager::new(test_key());

    // Add 100 workers with varying CPU usage
    for i in 0..100 {
        let id = format!("talos-worker-{i}");
        // CPU usage from 0% to 99%
        let cpu = i as f32;
        let hb = create_heartbeat(&id, cpu, vec!["wasm".to_string()]);
        manager.handle_heartbeat(hb).unwrap();
    }

    let best = manager
        .find_best_worker(&["wasm".to_string()])
        .expect("Should find a worker");
    assert_eq!(
        best.cpu_usage_pct, 0.0,
        "Should pick the worker with 0% CPU"
    );
    assert_eq!(manager.get_active_workers().len(), 100);
}

#[tokio::test]
async fn test_worker_updates_existing_entry() {
    let manager = WorkerManager::new(test_key());
    let id = "talos-worker-0";

    // Initial heartbeat: 50% CPU
    let hb1 = create_heartbeat(id, 50.0, vec!["wasm".to_string()]);
    manager.handle_heartbeat(hb1).unwrap();

    // Update heartbeat: 10% CPU
    let hb2 = create_heartbeat(id, 10.0, vec!["wasm".to_string()]);
    manager.handle_heartbeat(hb2).unwrap();

    let active = manager.get_active_workers();
    assert_eq!(active.len(), 1);
    assert_eq!(
        active[0].cpu_usage_pct, 10.0,
        "Worker stats should be updated"
    );
}
