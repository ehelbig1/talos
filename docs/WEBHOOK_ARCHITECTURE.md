# Webhook Listener Architecture

## Overview

Webhook listeners in Talos use a **centralized gateway pattern** where the Controller service manages all incoming webhooks and routes them to appropriate WASM modules for processing.

## Architecture

```
┌─────────────┐
│   Slack     │
│   GitHub    │──HTTP POST──┐
│   Others    │             │
└─────────────┘             ▼
                    ┌──────────────────┐
                    │ Controller       │
                    │                  │
                    │  Webhook Gateway │
                    │  /webhooks/:id   │
                    └────────┬─────────┘
                             │
                    ┌────────▼──────────┐
                    │ Webhook Router    │
                    │ - Auth/Verify     │
                    │ - Rate Limit      │
                    │ - Lookup Module   │
                    └────────┬──────────┘
                             │
                    ┌────────▼──────────┐
                    │ WASM Runtime      │
                    │ - Load Module     │
                    │ - Execute         │
                    │ - Return Response │
                    └────────┬──────────┘
                             │
                ┌────────────┴───────────────┐
                ▼                            ▼
        ┌──────────────┐           ┌──────────────┐
        │ Sync Response│           │ Event Queue  │
        │ (to caller)  │           │ (for async)  │
        └──────────────┘           └──────────────┘
```

## Database Schema

```sql
CREATE TABLE webhook_listeners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    module_id UUID REFERENCES wasm_modules(id),

    -- Security
    verification_token TEXT,  -- For validating incoming requests
    signing_secret TEXT,      -- For HMAC verification
    allowed_ips TEXT[],       -- IP whitelist

    -- Configuration
    enabled BOOLEAN DEFAULT true,
    auto_respond BOOLEAN DEFAULT true,  -- Return WASM output vs 200 OK

    -- Rate limiting
    max_requests_per_minute INTEGER DEFAULT 100,

    -- Metadata
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_triggered_at TIMESTAMPTZ,
    trigger_count INTEGER DEFAULT 0,

    -- Stats
    success_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    avg_response_ms FLOAT
);

CREATE INDEX idx_webhook_listeners_enabled ON webhook_listeners(enabled);
CREATE INDEX idx_webhook_listeners_module ON webhook_listeners(module_id);
```

## Request Flow

### 1. Incoming Webhook Request

```
POST /webhooks/550e8400-e29b-41d4-a716-446655440000
Headers:
  - X-Slack-Signature: v0=...
  - X-Slack-Request-Timestamp: 1234567890
Body: { JSON payload }
```

### 2. Gateway Processing

```rust
async fn handle_webhook(
    path: Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let listener_id = path.into_inner();

    // 1. Lookup listener config
    let listener = db.get_webhook_listener(listener_id).await?;

    if !listener.enabled {
        return Err(StatusCode::NOT_FOUND);
    }

    // 2. Security checks
    verify_request(&listener, &headers, &body)?;
    check_rate_limit(&listener).await?;

    // 3. Load and execute WASM
    let module_bytes = registry.get_module_bytes(listener.module_id).await?;
    let result = wasm_runtime.execute_with_timeout(
        module_bytes,
        body,
        Duration::from_secs(3)  // Slack requirement
    ).await?;

    // 4. Update stats
    db.increment_webhook_stats(listener_id, result.is_ok()).await?;

    // 5. Queue for async processing if configured
    if listener.queue_events {
        event_queue.push(WebhookEvent {
            listener_id,
            payload: body,
            result: result.clone(),
        }).await?;
    }

    // 6. Return response
    if listener.auto_respond {
        Ok(Response::new(result.unwrap()))
    } else {
        Ok(Response::new("OK"))
    }
}
```

### 3. Security Layers

**Layer 1: Obscured URLs**
- Each listener gets a unique UUID in the URL path
- Hard to guess, acts as first line of defense

**Layer 2: Verification Token**
- WASM module validates token from payload
- Slack sends this in every request

**Layer 3: HMAC Signature (Future)**
- Verify request signatures using signing secret
- Prevents replay attacks

**Layer 4: IP Allowlist (Future)**
- Only accept requests from known service IPs
- Slack publishes their IP ranges

**Layer 5: Rate Limiting**
- Per-listener request limits
- Prevents abuse/DoS

### 4. Performance Considerations

**WASM Module Caching**
```rust
struct WasmCache {
    modules: LruCache<Uuid, CompiledModule>,
    max_size: usize,
}
```
- Keep compiled WASM modules in memory (LRU cache)
- Avoid recompilation on every request
- Dramatically faster invocation (~1-5ms vs 100ms+)

**Connection Pooling**
- Reuse database connections
- Pool of WASM runtime instances

**Metrics**
- Track P50/P95/P99 response times
- Alert on slow modules (>2s)
- Auto-disable failing listeners

## Scaling Strategy

### Single Instance (MVP)
- Controller handles all webhooks
- Sufficient for 100s of listeners
- Sub-10ms overhead per request

### Multi-Instance (Future)
```
Load Balancer
    │
    ├─ Controller-1 (shared webhook table)
    ├─ Controller-2 (shared webhook table)
    └─ Controller-3 (shared webhook table)
```
- Shared PostgreSQL for listener config
- Redis for distributed rate limiting
- No sticky sessions needed (stateless)

### Dedicated Service (If Needed)
- Separate `webhook-gateway` service
- Controller focuses on workflow orchestration
- Only if webhook traffic is extremely high (10k+ RPS)

## Usage Example

### Creating a Slack Listener

1. User creates Slack webhook listener node
2. System generates listener ID: `550e8400-...`
3. User configures Slack app with URL: `https://talos.example.com/webhooks/550e8400-...`
4. Slack sends test event (url_verification)
5. WASM module responds with challenge
6. Listener is active!

### GraphQL Mutation

```graphql
mutation CreateWebhookListener {
  createWebhookListener(input: {
    name: "Slack Bot Messages"
    moduleId: "module-uuid-here"
    verificationToken: "xoxb-..."
    maxRequestsPerMinute: 60
  }) {
    id
    webhookUrl
  }
}
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "webhookUrl": "https://talos.example.com/webhooks/550e8400-e29b-41d4-a716-446655440000"
}
```

## Implementation Files

### Backend
- `controller/src/webhooks/mod.rs` - Gateway service
- `controller/src/webhooks/router.rs` - Request routing
- `controller/src/webhooks/security.rs` - Verification
- `controller/src/api/schema.rs` - GraphQL mutations

### Frontend
- `frontend/src/components/builder/WebhookConfig.tsx` - UI for webhook setup
- Shows generated webhook URL
- Copy-to-clipboard button
- Testing interface

## Testing Strategy

### Unit Tests
- WASM module parsing/validation
- Rate limiting logic
- Signature verification

### Integration Tests
```rust
#[tokio::test]
async fn test_slack_webhook_flow() {
    // Create listener
    let listener_id = create_test_listener().await;

    // Send mock Slack event
    let response = client
        .post(&format!("/webhooks/{}", listener_id))
        .json(&slack_message_event())
        .send()
        .await;

    assert_eq!(response.status(), 200);
    assert_eq!(response.text(), expected_wasm_output());
}
```

### Load Tests
- Apache Bench / k6 for simulating webhook traffic
- Target: 1000 RPS on single controller instance
- Monitor: CPU, memory, response times

## Monitoring & Observability

### Metrics
- `webhook_requests_total` - Counter by listener_id, status
- `webhook_response_time` - Histogram by listener_id
- `webhook_wasm_execution_time` - WASM-specific timing
- `webhook_rate_limit_hits` - Rate limiting events

### Logs
```json
{
  "event": "webhook_received",
  "listener_id": "550e8400-...",
  "source_ip": "1.2.3.4",
  "user_agent": "Slackbot 1.0",
  "response_time_ms": 45,
  "wasm_execution_ms": 12,
  "status": "success"
}
```

### Alerts
- Webhook response time > 2s
- Error rate > 5%
- Rate limit hit frequently (possible attack)

## Security Best Practices

1. **Never log sensitive tokens** - Use `[REDACTED]` in logs
2. **Validate all inputs** - WASM modules should never trust webhook payloads
3. **Timeout protection** - Kill WASM execution after 3s
4. **Memory limits** - Restrict WASM heap size
5. **Audit trail** - Log all webhook activations for debugging
6. **Secret rotation** - Support updating verification tokens

## Future Enhancements

### Phase 2: Async Workflows
- Webhook triggers workflow execution
- Return 200 immediately, process in background
- Workflow can take minutes/hours

### Phase 3: Webhook Transformers
- Chain multiple WASM modules
- Transform → Filter → Route
- Build complex integrations

### Phase 4: Webhook Replay
- Store last N webhook payloads
- Replay for debugging
- Reprocess failed events

### Phase 5: Multi-Region
- Deploy webhook gateways in multiple regions
- Route to nearest instance
- Global failover
