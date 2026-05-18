# Runtime-Enforced Best Practices for WASM Modules

**Date**: 2026-02-17
**Status**: Design Recommendations

---

## Philosophy: Enforce Through Architecture, Not Documentation

> **"Make the right thing easy and the wrong thing hard."**

By enforcing best practices at the **runtime level**, we ensure:
1. ✅ **Developers can't forget** - It's automatic
2. ✅ **Consistent behavior** - All modules follow same patterns
3. ✅ **Platform evolution** - Enhance without changing module code
4. ✅ **Security by default** - Vulnerabilities prevented at platform level

---

## ✅ Already Implemented

### 1. Automatic Logging
**Status**: ✅ Implemented

**What it does**:
- Automatic START/END logs for every execution
- Module logs via `logging::log()` → Database
- Guaranteed observability, cannot be bypassed

**Benefits**:
- Complete audit trail
- No silent failures
- Rich metadata (duration, status, errors)

---

## 🔥 High Priority - Should Implement Next

### 2. Automatic Error Handling & Recovery

**Problem**: Developers forget to handle errors properly, leading to:
- Panics that crash the entire execution
- Unhandled errors that provide no context
- Missing error logs
- No automatic retry on transient failures

**Solution**: Runtime-enforced error handling

```rust
// ========================================================================
// Runtime Wrapper (Automatic)
// ========================================================================

pub async fn execute_job_with_context(...) -> Result<JsonValue> {
    // ... setup ...

    // Wrap execution in panic handler
    let result = std::panic::AssertUnwindSafe(async {
        instance.call_run(&mut store, &input_str).await
    });

    let output_result = match std::panic::catch_unwind(|| {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(result)
    }) {
        Ok(ok_result) => ok_result,
        Err(panic_info) => {
            // Automatic panic logging
            let panic_msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };

            // Log panic automatically
            self.log_error(exec_id, &format!("WASM module panicked: {}", panic_msg)).await;

            // Return structured error instead of crashing
            return Err(anyhow!("Module panicked: {}", panic_msg));
        }
    };

    // Handle component errors
    match output_result {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(e)) => {
            // Automatic error logging
            self.log_error(exec_id, &format!("Module returned error: {}", e)).await;
            Err(anyhow!("Module error: {}", e))
        }
        Err(e) => {
            // Automatic runtime error logging
            self.log_error(exec_id, &format!("Runtime error: {}", e)).await;
            Err(e)
        }
    }
}
```

**Benefits**:
- ✅ **Panics don't crash workflows** - Caught and logged
- ✅ **All errors logged** - No silent failures
- ✅ **Structured error responses** - Consistent error format
- ✅ **Debugging context** - Automatic stack traces

**Implementation Effort**: 1 day

---

### 3. Automatic Timeout Enforcement

**Problem**: Long-running modules can:
- Block workflow execution indefinitely
- Consume resources unnecessarily
- Cause cascading delays

**Solution**: Runtime-enforced timeouts

```rust
pub async fn execute_job_with_context(...) -> Result<JsonValue> {
    // ... setup ...

    // Default timeout: 5 minutes (configurable per module)
    let timeout_duration = self.get_timeout_for_module(module_id)
        .unwrap_or(Duration::from_secs(300));

    // Automatic timeout wrapper
    let execution_future = instance.call_run(&mut store, &input_str);

    match tokio::time::timeout(timeout_duration, execution_future).await {
        Ok(result) => {
            // Completed within timeout
            result
        }
        Err(_) => {
            // Timeout exceeded - log and fail gracefully
            self.log_error(
                exec_id,
                &format!("Module timed out after {}s", timeout_duration.as_secs())
            ).await;

            // Update execution status
            exec_service.timeout_execution(exec_id, user_id).await?;

            Err(anyhow!("Execution timed out after {}s", timeout_duration.as_secs()))
        }
    }
}
```

**Benefits**:
- ✅ **Guaranteed termination** - No infinite loops
- ✅ **Resource protection** - Limits compute time
- ✅ **Predictable performance** - Workflows don't hang
- ✅ **Configurable per module** - Different timeouts for different needs

**Implementation Effort**: 0.5 days

---

### 4. Automatic Retry on Transient Failures

**Problem**: Network failures, rate limits, and transient errors cause:
- Unnecessary workflow failures
- Manual re-runs required
- Poor user experience

**Solution**: Runtime-enforced smart retries

```rust
pub async fn execute_job_with_context(...) -> Result<JsonValue> {
    // Retry configuration (from module metadata)
    let retry_config = RetryConfig {
        max_attempts: 3,
        initial_delay: Duration::from_secs(1),
        max_delay: Duration::from_secs(30),
        backoff_multiplier: 2.0,
        retryable_errors: vec![
            "network error",
            "timeout",
            "rate limit",
            "503",
            "429",
        ],
    };

    let mut attempt = 1;
    let mut delay = retry_config.initial_delay;

    loop {
        // Log retry attempt
        if attempt > 1 {
            self.log_info(
                exec_id,
                &format!("Retry attempt {}/{}", attempt, retry_config.max_attempts)
            ).await;
        }

        // Execute
        let result = instance.call_run(&mut store, &input_str).await;

        match result {
            Ok(Ok(output)) => {
                // Success!
                if attempt > 1 {
                    self.log_info(
                        exec_id,
                        &format!("Succeeded on attempt {}", attempt)
                    ).await;
                }
                return Ok(output);
            }
            Ok(Err(e)) | Err(e) => {
                let error_msg = e.to_string();

                // Check if error is retryable
                let is_retryable = retry_config.retryable_errors.iter()
                    .any(|pattern| error_msg.to_lowercase().contains(pattern));

                if is_retryable && attempt < retry_config.max_attempts {
                    // Wait before retry (exponential backoff)
                    self.log_warn(
                        exec_id,
                        &format!("Retryable error: {}. Waiting {}s before retry.", error_msg, delay.as_secs())
                    ).await;

                    tokio::time::sleep(delay).await;

                    // Increase delay for next retry
                    delay = (delay * retry_config.backoff_multiplier)
                        .min(retry_config.max_delay);

                    attempt += 1;
                } else {
                    // Non-retryable error or max attempts reached
                    if attempt >= retry_config.max_attempts {
                        self.log_error(
                            exec_id,
                            &format!("Failed after {} attempts: {}", attempt, error_msg)
                        ).await;
                    }
                    return Err(anyhow!(error_msg));
                }
            }
        }
    }
}
```

**Benefits**:
- ✅ **Resilient to transient failures** - Auto-retry on network errors
- ✅ **Exponential backoff** - Respects rate limits
- ✅ **Transparent to developers** - No retry code needed
- ✅ **Logged automatically** - Track retry attempts

**Configuration** (module metadata):
```json
{
  "module_id": "send-email",
  "retry": {
    "max_attempts": 3,
    "retryable_errors": ["network", "timeout", "rate limit"]
  }
}
```

**Implementation Effort**: 1 day

---

### 5. Automatic Performance Monitoring

**Problem**: Developers don't instrument code, leading to:
- No visibility into slow operations
- Can't identify bottlenecks
- No performance baselines

**Solution**: Runtime-enforced performance tracking

```rust
pub async fn execute_job_with_context(...) -> Result<JsonValue> {
    // Automatic performance tracking
    let perf_tracker = PerformanceTracker::new(exec_id, module_id);

    // Track compilation time
    let compile_start = Instant::now();
    let component = self.get_or_compile_component(wasm_bytes)?;
    perf_tracker.record("compile_ms", compile_start.elapsed().as_millis());

    // Track instantiation time
    let instantiate_start = Instant::now();
    let instance = AutomationNode::instantiate_async(&mut store, &component, &self.linker).await?;
    perf_tracker.record("instantiate_ms", instantiate_start.elapsed().as_millis());

    // Track execution time
    let exec_start = Instant::now();
    let result = instance.call_run(&mut store, &input_str).await;
    let exec_duration = exec_start.elapsed();
    perf_tracker.record("execute_ms", exec_duration.as_millis());

    // Track memory usage (if available)
    if let Ok(memory_pages) = store.data().get_memory_usage() {
        perf_tracker.record("memory_pages", memory_pages);
    }

    // Automatic performance logging
    perf_tracker.log_to_database(&self.exec_service).await;

    // Detect anomalies
    if exec_duration > Duration::from_secs(10) {
        self.log_warn(
            exec_id,
            &format!("Slow execution: {}ms (threshold: 10000ms)", exec_duration.as_millis())
        ).await;
    }

    result
}
```

**Benefits**:
- ✅ **Automatic metrics** - Compile, instantiate, execute times
- ✅ **Anomaly detection** - Slow executions flagged automatically
- ✅ **Performance baselines** - Track trends over time
- ✅ **No instrumentation code** - Zero developer effort

**Dashboard Queries**:
```sql
-- Slowest modules
SELECT module_id, AVG(execute_ms) as avg_ms
FROM performance_metrics
GROUP BY module_id
ORDER BY avg_ms DESC
LIMIT 10;

-- Performance over time
SELECT DATE(created_at), AVG(execute_ms)
FROM performance_metrics
WHERE module_id = $1
GROUP BY DATE(created_at);
```

**Implementation Effort**: 1 day

---

### 6. Automatic Resource Limits Enforcement

**Problem**: Modules can:
- Allocate excessive memory
- Make too many HTTP requests
- Open too many connections

**Solution**: Runtime-enforced resource quotas

```rust
pub struct ResourceLimits {
    max_memory_mb: usize,
    max_http_requests: u32,
    max_db_queries: u32,
    max_file_operations: u32,
    max_cache_operations: u32,
}

pub async fn execute_job_with_context(...) -> Result<JsonValue> {
    // Get resource limits for this module
    let limits = self.get_resource_limits(module_id);

    // Create resource tracker
    let mut context = TalosContext::new(...);
    context.set_resource_limits(limits);

    // Execute with automatic tracking
    let result = instance.call_run(&mut store, &input_str).await;

    // Check resource usage
    let usage = context.get_resource_usage();

    // Log if approaching limits
    if usage.http_requests > limits.max_http_requests * 80 / 100 {
        self.log_warn(
            exec_id,
            &format!(
                "HTTP request usage: {}/{} (80% of limit)",
                usage.http_requests,
                limits.max_http_requests
            )
        ).await;
    }

    result
}

// In TalosContext - enforce limits
impl HttpHost for TalosContext {
    async fn fetch(&mut self, req: http::Request) -> Result<http::Response, http::Error> {
        // Increment counter
        self.http_request_count += 1;

        // Automatic limit enforcement
        if self.http_request_count > self.limits.max_http_requests {
            return Err(http::Error::Networkerror); // Or custom error
        }

        // ... proceed with request ...
    }
}
```

**Benefits**:
- ✅ **Prevent resource exhaustion** - Hard limits enforced
- ✅ **Fair resource allocation** - No single module monopolizes
- ✅ **Cost control** - Limit expensive operations
- ✅ **Automatic warnings** - Alert before hitting limits

**Configuration**:
```json
{
  "module_id": "data-processor",
  "limits": {
    "max_memory_mb": 256,
    "max_http_requests": 100,
    "max_db_queries": 50
  }
}
```

**Implementation Effort**: 2 days

---

### 7. Automatic Result Caching

**Problem**: Expensive operations re-run unnecessarily:
- Same API calls repeated
- Identical database queries
- Redundant computations

**Solution**: Runtime-enforced intelligent caching

```rust
pub async fn execute_job_with_context(...) -> Result<JsonValue> {
    // Generate cache key (hash of: module_id + input + version)
    let cache_key = self.generate_cache_key(module_id, &input, module_version);

    // Check cache first (if module is cacheable)
    if let Some(cache_config) = self.get_cache_config(module_id) {
        if let Ok(Some(cached_result)) = self.redis_client.get(&cache_key).await {
            // Cache hit!
            self.log_info(
                exec_id,
                &format!("Cache hit - returning cached result (TTL: {}s)", cache_config.ttl_seconds)
            ).await;

            // Update metrics
            self.metrics.record_cache_hit(module_id);

            return Ok(serde_json::from_str(&cached_result)?);
        }
    }

    // Cache miss - execute normally
    let result = instance.call_run(&mut store, &input_str).await?;

    // Store result in cache (if cacheable)
    if let Some(cache_config) = self.get_cache_config(module_id) {
        let serialized = serde_json::to_string(&result)?;
        self.redis_client.setex(
            &cache_key,
            cache_config.ttl_seconds,
            &serialized
        ).await?;

        self.log_info(
            exec_id,
            "Result cached for future executions"
        ).await;
    }

    Ok(result)
}
```

**Benefits**:
- ✅ **Automatic performance boost** - Cached results return instantly
- ✅ **Reduced costs** - Fewer API calls, DB queries
- ✅ **Configurable per module** - Some modules cacheable, others not
- ✅ **Cache invalidation** - Automatic TTL expiration

**Configuration**:
```json
{
  "module_id": "weather-api",
  "cache": {
    "enabled": true,
    "ttl_seconds": 3600,
    "vary_by": ["input.location"]
  }
}
```

**Implementation Effort**: 1 day

---

## 🚀 Advanced - Future Enhancements

### 8. Automatic Input/Output Validation

**Problem**: Invalid data causes runtime errors

**Solution**: Schema validation at runtime

```rust
pub async fn execute_job_with_context(...) -> Result<JsonValue> {
    // Get JSON schema for this module
    let input_schema = self.registry.get_input_schema(module_id)?;

    // Automatic input validation
    if let Err(validation_errors) = jsonschema::validate(&input, &input_schema) {
        return Err(anyhow!("Input validation failed: {:?}", validation_errors));
    }

    // Execute
    let result = instance.call_run(&mut store, &input_str).await?;

    // Automatic output validation
    let output_schema = self.registry.get_output_schema(module_id)?;
    if let Err(validation_errors) = jsonschema::validate(&result, &output_schema) {
        self.log_error(exec_id, "Output validation failed").await;
        return Err(anyhow!("Output validation failed: {:?}", validation_errors));
    }

    Ok(result)
}
```

**Benefits**:
- ✅ **Catch errors early** - Invalid input rejected before execution
- ✅ **Type safety** - Ensure data contracts
- ✅ **Self-documenting** - Schema serves as documentation

---

### 9. Automatic Cost Tracking

**Problem**: No visibility into execution costs

**Solution**: Attribute costs automatically

```rust
pub async fn execute_job_with_context(...) -> Result<JsonValue> {
    let cost_tracker = CostTracker::new(exec_id);

    // Track compute costs
    cost_tracker.add_compute_cost(exec_duration, memory_usage);

    // Track API costs (in HTTP host impl)
    // cost_tracker.add_api_cost("openai", 0.002);

    // Save to database
    cost_tracker.save_to_db(&self.exec_service).await;

    // Monthly cost tracking
    let monthly_cost = self.get_monthly_cost(user_id).await?;
    if monthly_cost > user.cost_limit {
        return Err(anyhow!("Monthly cost limit exceeded: ${}", user.cost_limit));
    }

    Ok(result)
}
```

**Benefits**:
- ✅ **Cost visibility** - Know what each execution costs
- ✅ **Budget enforcement** - Prevent cost overruns
- ✅ **Billing attribution** - Charge customers accurately

---

### 10. Automatic Concurrency Control

**Problem**: Too many parallel executions overload system

**Solution**: Runtime-enforced concurrency limits

```rust
pub async fn execute_job_with_context(...) -> Result<JsonValue> {
    // Acquire semaphore (max concurrent executions per user)
    let permit = self.concurrency_limiter
        .acquire(user_id, max_concurrent_executions)
        .await?;

    // Execute (permit released automatically when dropped)
    let result = instance.call_run(&mut store, &input_str).await;

    drop(permit); // Explicit release

    result
}
```

**Benefits**:
- ✅ **System stability** - Prevent overload
- ✅ **Fair scheduling** - No single user monopolizes
- ✅ **Automatic queuing** - Requests wait gracefully

---

### 11. Automatic Security Scanning

**Problem**: Malicious or vulnerable code deployed

**Solution**: Runtime security checks

```rust
pub async fn execute_job_with_context(...) -> Result<JsonValue> {
    // Scan WASM bytes for known vulnerabilities
    let security_report = self.security_scanner.scan(wasm_bytes)?;

    if security_report.has_critical_issues() {
        return Err(anyhow!("Security check failed: {:?}", security_report.issues));
    }

    // Monitor suspicious behavior during execution
    let security_monitor = SecurityMonitor::new(exec_id);
    context.set_security_monitor(security_monitor);

    let result = instance.call_run(&mut store, &input_str).await;

    // Check for suspicious activity
    if security_monitor.detected_suspicious_activity() {
        self.alert_security_team(exec_id, security_monitor.get_report()).await;
    }

    result
}
```

---

## Implementation Priority

### Phase 1 (Week 1-2) - Critical
1. ✅ **Automatic Logging** - DONE
2. 🔥 **Automatic Error Handling** - High ROI, prevents crashes
3. 🔥 **Automatic Timeout Enforcement** - Prevents hangs

### Phase 2 (Week 3-4) - High Value
4. 🔥 **Automatic Retry** - Improves reliability
5. 🔥 **Automatic Performance Monitoring** - Essential observability
6. 🔥 **Automatic Resource Limits** - Prevents abuse

### Phase 3 (Month 2) - Enhanced Features
7. **Automatic Result Caching** - Performance optimization
8. **Automatic Input/Output Validation** - Data quality
9. **Automatic Cost Tracking** - Business intelligence

### Phase 4 (Month 3+) - Advanced
10. **Automatic Concurrency Control** - Scalability
11. **Automatic Security Scanning** - Security hardening

---

## Summary: The Power of Runtime Enforcement

By enforcing best practices at the **platform level**, we achieve:

### Benefits for Developers ✅
- **Zero boilerplate** - No error handling, retry, timeout code
- **Consistent patterns** - All modules behave the same
- **Focus on business logic** - Platform handles infrastructure
- **Impossible to forget** - Best practices automatic

### Benefits for Platform ✅
- **Complete observability** - Every execution tracked
- **Resource protection** - Limits prevent abuse
- **Security by default** - Vulnerabilities prevented
- **Performance optimization** - Automatic caching, monitoring

### Benefits for Business ✅
- **Cost control** - Track and limit spending
- **Reliability** - Auto-retry, error handling
- **Compliance** - Complete audit trail
- **Scalability** - Concurrency control, resource limits

---

## Recommendation

**Implement in this order**:

1. ✅ Logging (DONE)
2. Error Handling + Timeouts (1.5 days) - **START HERE**
3. Retry + Performance Monitoring (2 days)
4. Resource Limits (2 days)
5. Result Caching (1 day)

**Total effort**: ~1-2 weeks for critical features

**Impact**: Transform Talos from a WASM runtime into a **production-grade workflow platform** with enterprise-level reliability, observability, and security.

---

**This is how you build a platform developers love and businesses trust!** 🚀
