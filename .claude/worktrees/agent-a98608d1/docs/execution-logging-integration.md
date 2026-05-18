# Execution Logging Integration Guide

**Last Updated**: 2026-02-17

This guide shows how to add execution logging to any module (Slack, Gmail, custom webhooks, etc.) in just 3 simple steps.

---

## Quick Start (5 Minutes)

### Step 1: Add Service to Your Handler

```rust
use crate::node_executions::{NodeExecutionService, TriggerType, LogLevel};
use std::sync::Arc;

pub async fn your_webhook_handler(
    State(your_service): State<Arc<YourService>>,
    Extension(execution_service): Extension<Option<Arc<NodeExecutionService>>>,  // ← Add this
    // ... other parameters
) -> impl IntoResponse {
    // Annotate type for compiler clarity
    let execution_service: Option<Arc<NodeExecutionService>> = execution_service;

    // ... rest of handler
}
```

### Step 2: Wrap Your WASM Execution

```rust
// Get module and user IDs for your integration
let module_id = /* ... your logic to get module_id ... */;
let user_id = /* ... your logic to get user_id ... */;

// Create execution record
let execution_id = if let Some(exec_service) = execution_service.as_ref().map(Arc::clone) {
    // Create execution with metadata about the trigger
    let trigger_metadata = serde_json::json!({
        "webhook_type": "slack",      // or "gmail", "custom", etc.
        "event_id": event.id,
        "event_type": event.event_type,
        // ... any other relevant metadata
    });

    match exec_service.create_execution(
        module_id,
        user_id,
        TriggerType::Webhook,  // or ::Manual, ::Scheduled, ::Test
        Some(trigger_metadata),
        Some(event_json.clone()),  // The full input data
    ).await {
        Ok(id) => {
            // Mark as running (non-blocking, logs errors)
            exec_service.mark_running_best_effort(id).await;

            // Add initial log (non-blocking, logs errors)
            exec_service.add_log_best_effort(
                id,
                LogLevel::Info,
                format!("Processing {} event: {}", event.event_type, event.id),
                None
            ).await;

            Some(id)
        }
        Err(e) => {
            tracing::warn!("Failed to create execution record: {}", e);
            None  // Continue execution even if logging fails
        }
    }
} else {
    None  // Service not available (optional dependency)
};

// Execute your WASM module
let result = tokio::time::timeout(
    std::time::Duration::from_secs(30),
    runtime.execute_module_string(&wasm_bytes, &input)
).await;

// Update execution based on result
match result {
    Ok(Ok(output)) => {
        // SUCCESS
        if let (Some(exec_service), Some(exec_id)) = (
            execution_service.as_ref().map(Arc::clone),
            execution_id
        ) {
            let output_json = serde_json::from_str(&output).ok();
            exec_service.complete_execution_best_effort(exec_id, output_json, None, None).await;
            exec_service.add_log_best_effort(
                exec_id,
                LogLevel::Info,
                "Execution completed successfully",
                None
            ).await;
        }
        StatusCode::OK
    }
    Ok(Err(e)) => {
        // RUNTIME ERROR
        if let (Some(exec_service), Some(exec_id)) = (
            execution_service.as_ref().map(Arc::clone),
            execution_id
        ) {
            exec_service.fail_execution_best_effort(
                exec_id,
                e.to_string(),
                Some("runtime".to_string())
            ).await;
            exec_service.add_log_best_effort(
                exec_id,
                LogLevel::Error,
                format!("Execution failed: {}", e),
                None
            ).await;
        }
        StatusCode::INTERNAL_SERVER_ERROR
    }
    Err(_) => {
        // TIMEOUT
        if let (Some(exec_service), Some(exec_id)) = (
            execution_service.as_ref().map(Arc::clone),
            execution_id
        ) {
            exec_service.timeout_execution_best_effort(exec_id).await;
            exec_service.add_log_best_effort(
                exec_id,
                LogLevel::Error,
                "Execution timed out after 30 seconds",
                None
            ).await;
        }
        StatusCode::REQUEST_TIMEOUT
    }
}
```

### Step 3: Add Service to Your Routes

If your routes don't already have the execution service:

```rust
// In main.rs
let your_webhook_routes = Router::new()
    .route("/api/your-module/webhook", post(your_webhook_handler))
    .with_state(your_service.clone())
    .layer(Extension(node_execution_service.clone()));  // ← Add this line
```

**That's it!** Your executions are now logged to the database.

---

## API Reference

### TriggerType

```rust
pub enum TriggerType {
    Webhook,    // External webhook triggered
    Manual,     // User clicked "Run" in UI
    Scheduled,  // Cron/timer triggered
    Test,       // Development/testing
}
```

### LogLevel

```rust
pub enum LogLevel {
    Debug,  // Verbose debugging info
    Info,   // Normal informational messages
    Warn,   // Warnings (non-fatal issues)
    Error,  // Errors (failures)
}
```

### Service Methods

#### Primary Methods (return Result)

```rust
// Create execution record (returns execution_id)
async fn create_execution(
    &self,
    module_id: Uuid,
    user_id: Uuid,
    trigger_type: TriggerType,
    trigger_metadata: Option<JsonValue>,  // Arbitrary JSON metadata
    input_data: Option<JsonValue>,         // Input sent to WASM
) -> Result<Uuid>

// Update status to running
async fn mark_running(&self, execution_id: Uuid) -> Result<()>

// Mark as completed successfully
async fn complete_execution(
    &self,
    execution_id: Uuid,
    output_data: Option<JsonValue>,     // WASM output
    fuel_consumed: Option<i64>,         // Optional: WASM fuel used
    memory_used_mb: Option<i32>,        // Optional: Peak memory
) -> Result<()>

// Mark as failed with error
async fn fail_execution(
    &self,
    execution_id: Uuid,
    error_message: String,              // Auto-truncated to 10KB
    error_type: Option<String>,         // e.g., "runtime", "validation", "timeout"
) -> Result<()>

// Mark as timed out
async fn timeout_execution(&self, execution_id: Uuid) -> Result<()>

// Add log entry (rate limited to 1000 per execution)
async fn add_log(
    &self,
    execution_id: Uuid,
    level: LogLevel,
    message: String,
    metadata: Option<JsonValue>,        // Optional structured data
) -> Result<()>
```

#### Best-Effort Methods (never fail, log errors)

**RECOMMENDED**: Use these in webhook handlers to avoid blocking execution on logging failures.

```rust
// Same as above, but logs errors instead of returning them
async fn mark_running_best_effort(&self, execution_id: Uuid)
async fn complete_execution_best_effort(&self, execution_id: Uuid, ...)
async fn fail_execution_best_effort(&self, execution_id: Uuid, ...)
async fn timeout_execution_best_effort(&self, execution_id: Uuid)
async fn add_log_best_effort(&self, execution_id: Uuid, ...)
```

---

## Complete Examples

### Example 1: Slack Integration

```rust
use crate::node_executions::{NodeExecutionService, TriggerType, LogLevel};

pub async fn slack_event_handler(
    State(slack_service): State<Arc<SlackService>>,
    Extension(execution_service): Extension<Option<Arc<NodeExecutionService>>>,
    Json(event): Json<SlackEvent>,
) -> impl IntoResponse {
    let execution_service: Option<Arc<NodeExecutionService>> = execution_service;

    // Get module for this Slack workspace
    let (module_id, user_id) = match slack_service.get_module_for_team(&event.team_id).await {
        Ok(Some((m, u))) => (m, u),
        Ok(None) => return StatusCode::NOT_FOUND,
        Err(e) => {
            tracing::error!("Failed to get module: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    // Create execution
    let execution_id = if let Some(exec_service) = execution_service.as_ref().map(Arc::clone) {
        match exec_service.create_execution(
            module_id,
            user_id,
            TriggerType::Webhook,
            Some(serde_json::json!({
                "event_type": event.event_type,
                "event_id": event.event_id,
                "team_id": event.team_id,
                "user_id": event.user_id,
            })),
            Some(serde_json::to_value(&event).ok()),
        ).await {
            Ok(id) => {
                exec_service.mark_running_best_effort(id).await;
                exec_service.add_log_best_effort(
                    id,
                    LogLevel::Info,
                    format!("Processing Slack {} event", event.event_type),
                    None
                ).await;
                Some(id)
            }
            Err(e) => {
                tracing::warn!("Failed to create execution: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Get WASM bytes
    let wasm_bytes = match slack_service.get_module_bytes(module_id).await {
        Ok(bytes) => bytes,
        Err(e) => {
            if let (Some(svc), Some(id)) = (execution_service.as_ref().map(Arc::clone), execution_id) {
                svc.fail_execution_best_effort(
                    id,
                    format!("Failed to load module: {}", e),
                    Some("module_load".to_string())
                ).await;
            }
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    // Execute WASM
    let runtime = TalosRuntime::new().unwrap();
    let input = serde_json::to_string(&event).unwrap();

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        runtime.execute_module_string(&wasm_bytes, &input)
    ).await;

    // Handle result
    match result {
        Ok(Ok(output)) => {
            if let (Some(svc), Some(id)) = (execution_service.as_ref().map(Arc::clone), execution_id) {
                svc.complete_execution_best_effort(id, serde_json::from_str(&output).ok(), None, None).await;
            }
            StatusCode::OK
        }
        Ok(Err(e)) => {
            if let (Some(svc), Some(id)) = (execution_service.as_ref().map(Arc::clone), execution_id) {
                svc.fail_execution_best_effort(id, e.to_string(), Some("runtime".to_string())).await;
            }
            StatusCode::INTERNAL_SERVER_ERROR
        }
        Err(_) => {
            if let (Some(svc), Some(id)) = (execution_service.as_ref().map(Arc::clone), execution_id) {
                svc.timeout_execution_best_effort(id).await;
            }
            StatusCode::REQUEST_TIMEOUT
        }
    }
}
```

### Example 2: Manual Execution (UI "Run" Button)

```rust
pub async fn execute_node_manually(
    State(node_service): State<Arc<NodeService>>,
    Extension(execution_service): Extension<Arc<NodeExecutionService>>,  // Required for manual runs
    Extension(user_id): Extension<Uuid>,
    Path(node_id): Path<Uuid>,
    Json(input): Json<JsonValue>,
) -> Result<Json<JsonValue>, StatusCode> {
    // Get module for this node
    let module_id = match node_service.get_module_id(node_id).await {
        Ok(Some(id)) => id,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    // Create execution record
    let execution_id = execution_service.create_execution(
        module_id,
        user_id,
        TriggerType::Manual,  // User-initiated
        Some(serde_json::json!({"node_id": node_id})),
        Some(input.clone()),
    ).await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    execution_service.mark_running_best_effort(execution_id).await;

    // Execute WASM
    let wasm_bytes = node_service.get_module_bytes(module_id).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let runtime = TalosRuntime::new().unwrap();
    let input_str = serde_json::to_string(&input).unwrap();

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        runtime.execute_module_string(&wasm_bytes, &input_str)
    ).await;

    match result {
        Ok(Ok(output)) => {
            let output_json: JsonValue = serde_json::from_str(&output)
                .unwrap_or(serde_json::json!({"raw": output}));

            execution_service.complete_execution_best_effort(
                execution_id,
                Some(output_json.clone()),
                None,
                None
            ).await;

            Ok(Json(output_json))
        }
        Ok(Err(e)) => {
            execution_service.fail_execution_best_effort(
                execution_id,
                e.to_string(),
                Some("runtime".to_string())
            ).await;
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
        Err(_) => {
            execution_service.timeout_execution_best_effort(execution_id).await;
            Err(StatusCode::REQUEST_TIMEOUT)
        }
    }
}
```

---

## Best Practices

### ✅ DO

- **Use `_best_effort` methods** in webhook handlers (non-blocking)
- **Add meaningful trigger_metadata** (helps with debugging)
- **Log intermediate steps** with `add_log_best_effort`
- **Store full input/output** for debugging (automatically truncated if too large)
- **Use appropriate TriggerType** (Webhook vs Manual vs Scheduled)

### ❌ DON'T

- **Don't use `.await?` on logging methods** in critical paths (use `_best_effort` instead)
- **Don't create executions without user_id** (breaks authorization)
- **Don't log PII** in messages (use metadata with sanitized data)
- **Don't create excessive logs** (automatically rate limited to 1000/execution)

---

## Troubleshooting

### Q: Execution service is None in my handler?

**A**: Add the service to your routes:
```rust
.layer(Extension(node_execution_service.clone()))
```

### Q: How do I query execution logs?

**A**: Use the service methods (requires authorization):
```rust
// Get specific execution
let execution = execution_service.get_execution(execution_id, user_id).await?;

// Get recent executions for a module
let executions = execution_service.get_module_executions(module_id, user_id, 50).await?;

// Get logs for an execution
let logs = execution_service.get_execution_logs(execution_id, user_id).await?;
```

### Q: Can I add custom fields to executions?

**A**: Use the `trigger_metadata` and log `metadata` fields (both JSONB):
```rust
let trigger_metadata = serde_json::json!({
    "custom_field_1": "value",
    "custom_field_2": 123,
    "nested": {"data": "here"}
});

exec_service.add_log_best_effort(
    execution_id,
    LogLevel::Info,
    "Custom event",
    Some(serde_json::json!({"my": "data"}))
).await;
```

---

## Database Schema

### node_executions Table

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| module_id | UUID | WASM module that executed |
| user_id | UUID | Owner (for authorization) |
| status | TEXT | pending, running, completed, failed, timeout |
| trigger_type | TEXT | webhook, manual, scheduled, test |
| trigger_metadata | JSONB | Custom metadata about trigger |
| input_data | JSONB | Input sent to WASM |
| output_data | JSONB | Output from WASM (NULL if failed) |
| started_at | TIMESTAMPTZ | When execution started |
| completed_at | TIMESTAMPTZ | When execution finished |
| duration_ms | INTEGER | Auto-calculated duration |
| error_message | STRING | Error (auto-truncated to 10KB) |
| error_type | STRING | Error category (runtime, timeout, etc.) |
| fuel_consumed | BIGINT | WASM fuel used (optional) |
| memory_used_mb | INTEGER | Peak memory (optional) |
| created_at | TIMESTAMPTZ | Record creation time |
| updated_at | TIMESTAMPTZ | Auto-updated on changes |

### node_execution_logs Table

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| execution_id | UUID | Foreign key to node_executions |
| level | TEXT | DEBUG, INFO, WARN, ERROR |
| message | TEXT | Log message |
| metadata | JSONB | Structured log data |
| created_at | TIMESTAMPTZ | Log timestamp |

---

## Performance Notes

- **Overhead**: ~15-30ms per execution (< 5% of typical WASM execution)
- **Rate Limiting**: Max 1000 logs per execution (prevents DoS)
- **Message Truncation**: Error messages auto-truncated to 10KB
- **Indexes**: All queries optimized with proper indexes
- **Async**: All operations are non-blocking

---

## Support

- **Documentation**: `/docs/execution-logging-integration.md`
- **Review**: `EXECUTION_LOGGING_REVIEW.md`
- **Schema**: `migrations/012_node_executions.sql`
- **Source**: `controller/src/node_executions.rs`

For questions or issues, see the main implementation documentation.
