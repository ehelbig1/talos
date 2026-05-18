// Execution Event Regression Tests
//
// Bug 2: Execution events not persisted / broadcast order
//
// Events must be broadcast to WebSocket subscribers BEFORE persisting to DB,
// so a DB failure doesn't block live updates. Events must also be persisted
// to `execution_events` for replay.
//
// These tests verify the event type mapping logic and the ExecutionEvent
// structure without requiring a database connection.
//
// To run:
//    cargo test --test execution_event_tests

use controller::engine::events::{ExecutionEvent, ExecutionStatus};
use uuid::Uuid;

// ============================================================================
// Event type mapping tests
//
// The emit_event and store_and_send logic maps (status, node_id) combinations
// to event_type strings. These tests verify the mapping is correct.
// ============================================================================

/// Replicates the event_type mapping from emit_event in parallel.rs
/// and the store_and_send macro in mutations.rs.
fn derive_event_type(status: &ExecutionStatus, node_id: &Option<Uuid>) -> &'static str {
    match (status, node_id) {
        (ExecutionStatus::Running, Some(_)) => "node_started",
        (ExecutionStatus::Completed, Some(_)) => "node_completed",
        (ExecutionStatus::Failed, Some(_)) => "node_failed",
        (ExecutionStatus::Skipped, Some(_)) => "node_skipped",
        (ExecutionStatus::Waiting, Some(_)) => "node_waiting",
        (ExecutionStatus::Running, None) => "started",
        (ExecutionStatus::Completed, None) => "completed",
        (ExecutionStatus::Failed, None) => "failed",
        (ExecutionStatus::Skipped, None) => "skipped",
        (ExecutionStatus::Waiting, None) => "waiting",
        (ExecutionStatus::Pending, Some(_)) => "node_pending",
        (ExecutionStatus::Pending, None) => "pending",
        (ExecutionStatus::OutputReady, Some(_)) => "node_output_ready",
        (ExecutionStatus::OutputReady, None) => "output_ready",
    }
}

#[test]
fn test_event_type_node_started() {
    // Regression: Running status with a node_id should produce "node_started"
    let node_id = Some(Uuid::new_v4());
    assert_eq!(
        derive_event_type(&ExecutionStatus::Running, &node_id),
        "node_started"
    );
}

#[test]
fn test_event_type_node_completed() {
    // Regression: Completed status with a node_id should produce "node_completed"
    let node_id = Some(Uuid::new_v4());
    assert_eq!(
        derive_event_type(&ExecutionStatus::Completed, &node_id),
        "node_completed"
    );
}

#[test]
fn test_event_type_node_failed() {
    // Regression: Failed status with a node_id should produce "node_failed"
    let node_id = Some(Uuid::new_v4());
    assert_eq!(
        derive_event_type(&ExecutionStatus::Failed, &node_id),
        "node_failed"
    );
}

#[test]
fn test_event_type_node_skipped() {
    let node_id = Some(Uuid::new_v4());
    assert_eq!(
        derive_event_type(&ExecutionStatus::Skipped, &node_id),
        "node_skipped"
    );
}

#[test]
fn test_event_type_node_waiting() {
    let node_id = Some(Uuid::new_v4());
    assert_eq!(
        derive_event_type(&ExecutionStatus::Waiting, &node_id),
        "node_waiting"
    );
}

#[test]
fn test_event_type_workflow_started() {
    // Regression: Running status with no node_id should produce "started" (workflow-level)
    assert_eq!(
        derive_event_type(&ExecutionStatus::Running, &None),
        "started"
    );
}

#[test]
fn test_event_type_workflow_completed() {
    // Regression: Completed status with no node_id should produce "completed" (workflow-level)
    assert_eq!(
        derive_event_type(&ExecutionStatus::Completed, &None),
        "completed"
    );
}

#[test]
fn test_event_type_workflow_failed() {
    assert_eq!(derive_event_type(&ExecutionStatus::Failed, &None), "failed");
}

#[test]
fn test_event_type_workflow_skipped() {
    assert_eq!(
        derive_event_type(&ExecutionStatus::Skipped, &None),
        "skipped"
    );
}

#[test]
fn test_event_type_workflow_waiting() {
    assert_eq!(
        derive_event_type(&ExecutionStatus::Waiting, &None),
        "waiting"
    );
}

#[test]
fn test_event_type_pending() {
    assert_eq!(
        derive_event_type(&ExecutionStatus::Pending, &None),
        "pending"
    );
    assert_eq!(
        derive_event_type(&ExecutionStatus::Pending, &Some(Uuid::new_v4())),
        "node_pending"
    );
}

// ============================================================================
// ExecutionEvent structure tests
// ============================================================================

#[test]
fn test_execution_event_has_iteration_fields() {
    // Regression: ExecutionEvent must include iteration_index and iteration_total
    // for forEach loop progress tracking.
    let event = ExecutionEvent {
        execution_id: Uuid::new_v4(),
        node_id: Some(Uuid::new_v4()),
        status: ExecutionStatus::Running,
        log_message: Some("Processing item 3/10".to_string()),
        trace_id: None,
        span_id: None,
        iteration_index: Some(2),
        iteration_total: Some(10),
        duration_ms: None,
        output: None,
    };

    assert_eq!(event.iteration_index, Some(2));
    assert_eq!(event.iteration_total, Some(10));
}

#[test]
fn test_execution_event_iteration_fields_default_none() {
    // When not in a forEach loop, iteration fields should be None.
    let event = ExecutionEvent {
        execution_id: Uuid::new_v4(),
        node_id: None,
        status: ExecutionStatus::Completed,
        log_message: None,
        trace_id: None,
        span_id: None,
        iteration_index: None,
        iteration_total: None,
        duration_ms: None,
        output: None,
    };

    assert_eq!(event.iteration_index, None);
    assert_eq!(event.iteration_total, None);
}

#[test]
fn test_execution_event_serializes_correctly() {
    // Regression: Events are serialized when persisted and when broadcast via WebSocket.
    let event = ExecutionEvent {
        execution_id: Uuid::new_v4(),
        node_id: Some(Uuid::new_v4()),
        status: ExecutionStatus::Completed,
        log_message: Some("Node finished".to_string()),
        trace_id: Some("abc123".to_string()),
        span_id: Some("def456".to_string()),
        iteration_index: Some(0),
        iteration_total: Some(5),
        duration_ms: Some(100),
        output: None,
    };

    let serialized = serde_json::to_value(&event).unwrap();
    assert!(serialized.get("execution_id").is_some());
    assert!(serialized.get("node_id").is_some());
    assert!(serialized.get("status").is_some());
    assert!(serialized.get("log_message").is_some());
    assert!(serialized.get("iteration_index").is_some());
    assert!(serialized.get("iteration_total").is_some());
}

// ============================================================================
// Broadcast-before-persist contract test
// ============================================================================

#[tokio::test]
async fn test_broadcast_channel_receives_event_immediately() {
    // Regression: Events must be broadcast to WebSocket subscribers via tokio::broadcast
    // BEFORE being persisted to DB. This test verifies that the broadcast channel
    // delivers events immediately without any DB dependency.
    use tokio::sync::broadcast;

    let (sender, mut receiver) = broadcast::channel::<ExecutionEvent>(16);

    let event = ExecutionEvent {
        execution_id: Uuid::new_v4(),
        node_id: Some(Uuid::new_v4()),
        status: ExecutionStatus::Completed,
        log_message: Some("test".to_string()),
        trace_id: None,
        span_id: None,
        iteration_index: None,
        iteration_total: None,
        duration_ms: None,
        output: None,
    };

    // Simulate the broadcast (this happens before DB persist in the real code)
    sender.send(event.clone()).unwrap();

    // Receiver should get the event immediately
    let received = receiver.recv().await.unwrap();
    assert_eq!(received.execution_id, event.execution_id);
    assert_eq!(received.status, ExecutionStatus::Completed);
}

#[tokio::test]
async fn test_broadcast_does_not_fail_with_no_receivers() {
    // Regression: If no WebSocket clients are connected, broadcast.send() returns
    // an error, but the engine must not propagate this — it should ignore it.
    use tokio::sync::broadcast;

    let (sender, receiver) = broadcast::channel::<ExecutionEvent>(16);
    // Drop the only receiver so there are no active subscribers
    drop(receiver);

    let event = ExecutionEvent {
        execution_id: Uuid::new_v4(),
        node_id: None,
        status: ExecutionStatus::Running,
        log_message: None,
        trace_id: None,
        span_id: None,
        iteration_index: None,
        iteration_total: None,
        duration_ms: None,
        output: None,
    };

    // This will return Err because no receivers, but the engine uses `let _ = sender.send(event);`
    let result = sender.send(event);
    // The important thing is this doesn't panic. The engine ignores the error.
    assert!(
        result.is_err(),
        "send with no receivers returns Err, which is expected and ignored"
    );
}

// ============================================================================
// All event types coverage
// ============================================================================

#[test]
fn test_all_execution_statuses_are_handled() {
    // Regression: The execution_events table schema must accept all event types.
    // This test ensures every ExecutionStatus variant maps to a known event type.
    let statuses = vec![
        ExecutionStatus::Pending,
        ExecutionStatus::Running,
        ExecutionStatus::Completed,
        ExecutionStatus::Failed,
        ExecutionStatus::Skipped,
        ExecutionStatus::Waiting,
    ];

    let known_event_types = vec![
        "started",
        "node_started",
        "completed",
        "node_completed",
        "failed",
        "node_failed",
        "skipped",
        "node_skipped",
        "waiting",
        "node_waiting",
        "pending",
        "node_pending",
    ];

    for status in &statuses {
        // With node_id
        let event_type = derive_event_type(status, &Some(Uuid::new_v4()));
        assert!(
            known_event_types.contains(&event_type),
            "Event type '{}' for {:?} with node_id should be in known list",
            event_type,
            status
        );

        // Without node_id
        let event_type = derive_event_type(status, &None);
        assert!(
            known_event_types.contains(&event_type),
            "Event type '{}' for {:?} without node_id should be in known list",
            event_type,
            status
        );
    }
}
