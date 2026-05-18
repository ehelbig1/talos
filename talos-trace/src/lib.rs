/// Distributed tracing support for WASM execution
///
/// This module provides OpenTelemetry tracing integration for tracking:
/// - Execution spans across workflow steps
/// - Performance profiling with nested spans
/// - Error tracking and classification
/// - Request correlation with trace IDs
///
/// # Integration
/// - Jaeger: For viewing distributed traces
/// - Zipkin: Alternative trace visualization
/// - OpenTelemetry Collector: Central trace aggregation
///
/// # Usage
/// ```rust
/// // Doctests run in an isolated crate, so we import the public API and
/// // return a `Result`.
/// use worker::tracing::{init_tracing, ExecutionSpan};
///
/// fn example() -> Result<(), Box<dyn std::error::Error>> {
///     // Initialize tracing (endpoint optional)
///     init_tracing("talos-worker", Some("http://jaeger:14268/api/traces"))?;
///
///     // Create a span for execution
///     let mut span = ExecutionSpan::new("workflow-execution", "exec-123");
///     span.set_attribute("workflow_id", "wf-456");
///
///     // Execution happens here...
///
///     span.end_success(); // or span.end_error("error message")
///     Ok(())
/// }
/// ```
#[allow(dead_code)]
use opentelemetry::{
    global,
    trace::{Span, SpanKind, Status, Tracer, TracerProvider},
    KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use std::time::Instant;

/// Initialize OpenTelemetry tracing
/// Sets up the global tracer provider with OTLP exporter (for Jaeger)
///
/// # Arguments
/// * `service_name` - Name of the service (e.g., "talos-worker")
/// * `endpoint` - OTLP gRPC endpoint (e.g., "http://jaeger:4317")
///
/// # Example
/// ```rust
/// // Send traces to Jaeger via OTLP
/// use worker::tracing::init_tracing;
/// fn example() -> Result<(), Box<dyn std::error::Error>> {
///     init_tracing("talos-worker", Some("http://localhost:4317"))?;
///     Ok(())
/// }
/// ```
pub fn init_tracing(
    service_name: &str,
    endpoint: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // If no endpoint provided, skip tracing setup
    let endpoint = match endpoint {
        Some(ep) => ep,
        None => {
            println!("[TRACING] No endpoint configured, tracing disabled");
            return Ok(());
        }
    };

    println!(
        "[TRACING] Initializing OpenTelemetry for service: {}",
        service_name
    );
    println!("[TRACING] OTLP endpoint: {}", endpoint);

    // Build tracer provider with OTLP exporter
    use opentelemetry_otlp::SpanExporter;
    use opentelemetry_sdk::trace::TracerProvider;

    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    // Sampler configuration omitted for simplicity – defaults to always_on.

    let tracer_provider = TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_resource(Resource::new(vec![
            KeyValue::new("service.name", service_name.to_string()),
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION").to_string()),
        ]))
        .build();

    // Set as global tracer provider
    global::set_tracer_provider(tracer_provider);

    println!("[TRACING] ✅ OpenTelemetry tracing initialized successfully");
    println!("[TRACING] Traces will be exported to: {}", endpoint);

    Ok(())
}

/// Shutdown tracing gracefully
/// Call this before application exit to flush remaining traces
pub fn shutdown_tracing() {
    println!("[TRACING] Shutting down tracing, flushing remaining spans...");
    global::shutdown_tracer_provider();
    println!("[TRACING] ✅ Tracing shutdown complete");
}

/// Execution span for distributed tracing
/// Wraps OpenTelemetry span with WASM-specific functionality
pub struct ExecutionSpan {
    span: opentelemetry::global::BoxedSpan,
    start_time: Instant,
    name: String,
    execution_id: String,
}

#[allow(dead_code)]
impl ExecutionSpan {
    /// Create a new execution span
    ///
    /// # Arguments
    /// * `name` - Span name (e.g., "wasm-execution", "http-request")
    /// * `execution_id` - Unique execution identifier
    ///
    /// # Example
    /// ```rust
    /// use worker::tracing::ExecutionSpan;
    /// let span = ExecutionSpan::new("workflow-step", "exec-123");
    /// ```
    pub fn new(name: &str, execution_id: &str) -> Self {
        // Get the global tracer provider and create a concrete span
        let provider = global::tracer_provider();
        let tracer = provider.tracer("talos-wasm-runtime");

        let mut span = tracer
            .span_builder(name.to_string())
            .with_kind(SpanKind::Internal)
            .start(&tracer);

        // Add standard attributes
        span.set_attribute(KeyValue::new("execution.id", execution_id.to_string()));
        span.set_attribute(KeyValue::new("service.name", "talos-worker"));
        span.set_attribute(KeyValue::new("component", "wasm-runtime"));

        Self {
            span,
            start_time: Instant::now(),
            name: name.to_string(),
            execution_id: execution_id.to_string(),
        }
    }

    /// Create a child span (for nested operations)
    ///
    /// # Example
    /// ```rust
    /// // Import the type for doctest
    /// use worker::tracing::ExecutionSpan;
    ///
    /// fn example() -> Result<(), Box<dyn std::error::Error>> {
    ///     let parent = ExecutionSpan::new("workflow", "exec-123");
    ///     let _child = parent.child("http-request");
    ///     Ok(())
    /// }
    /// ```
    pub fn child(&self, name: &str) -> Self {
        // Get the global tracer provider and create a concrete span
        let provider = global::tracer_provider();
        let tracer = provider.tracer("talos-wasm-runtime");

        let mut span = tracer
            .span_builder(name.to_string())
            .with_kind(SpanKind::Internal)
            .start(&tracer);

        // Inherit parent attributes
        span.set_attribute(KeyValue::new("execution.id", self.execution_id.clone()));
        span.set_attribute(KeyValue::new("parent.span", self.name.clone()));

        Self {
            span,
            start_time: Instant::now(),
            name: name.to_string(),
            execution_id: self.execution_id.clone(),
        }
    }

    /// Set a custom attribute on the span
    ///
    /// # Example
    /// ```rust
    /// use worker::tracing::ExecutionSpan;
    ///
    /// fn example() -> Result<(), Box<dyn std::error::Error>> {
    ///     let mut span = ExecutionSpan::new("example", "id-1");
    ///     span.set_attribute("workflow_id", "wf-456");
    ///     span.set_attribute("module_id", "mod-789");
    ///     span.set_attribute("cache_hit", "true");
    ///     Ok(())
    /// }
    /// ```
    pub fn set_attribute(&mut self, key: &str, value: &str) {
        self.span
            .set_attribute(KeyValue::new(key.to_string(), value.to_string()));
    }

    /// Set an integer attribute
    pub fn set_attribute_int(&mut self, key: &str, value: i64) {
        self.span
            .set_attribute(KeyValue::new(key.to_string(), value));
    }

    /// Set a boolean attribute
    pub fn set_attribute_bool(&mut self, key: &str, value: bool) {
        self.span
            .set_attribute(KeyValue::new(key.to_string(), value));
    }

    /// Record an event in the span
    ///
    /// # Example
    /// ```rust
    /// use worker::tracing::ExecutionSpan;
    ///
    /// fn example() -> Result<(), Box<dyn std::error::Error>> {
    ///     let mut span = ExecutionSpan::new("example", "id-1");
    ///     span.add_event("compilation_started");
    ///     span.add_event("cache_hit");
    ///     span.add_event("execution_completed");
    ///     Ok(())
    /// }
    /// ```
    pub fn add_event(&mut self, name: &str) {
        self.span.add_event(name.to_string(), vec![]);
    }

    /// Record an event with attributes
    ///
    /// # Example
    /// ```rust
    /// use worker::tracing::ExecutionSpan;
    ///
    /// fn example() -> Result<(), Box<dyn std::error::Error>> {
    ///     let mut span = ExecutionSpan::new("example", "id-1");
    ///     span.add_event_with_attributes("http_request", vec![
    ///         ("url", "https://api.example.com"),
    ///         ("status", "200"),
    ///     ]);
    ///     Ok(())
    /// }
    /// ```
    pub fn add_event_with_attributes(&mut self, name: &str, attributes: Vec<(&str, &str)>) {
        let attrs: Vec<KeyValue> = attributes
            .iter()
            .map(|(k, v)| KeyValue::new(k.to_string(), v.to_string()))
            .collect();

        self.span.add_event(name.to_string(), attrs);
    }

    /// Get the execution duration so far
    pub fn duration_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }

    /// End the span successfully
    ///
    /// # Example
    /// ```rust
    /// use worker::tracing::ExecutionSpan;
    /// fn example() -> Result<(), Box<dyn std::error::Error>> {
    ///     let span = ExecutionSpan::new("execution", "exec-123");
    ///     // ... do work ...
    ///     span.end_success();
    ///     Ok(())
    /// }
    /// ```
    pub fn end_success(mut self) {
        let duration = self.duration_ms();
        self.span
            .set_attribute(KeyValue::new("duration_ms", duration as i64));
        self.span.set_status(Status::Ok);
        self.span.end();

        println!(
            "[TRACE] Span '{}' completed successfully in {}ms (execution_id: {})",
            self.name, duration, self.execution_id
        );
    }

    /// End the span with an error
    ///
    /// # Example
    /// ```rust
    /// use worker::tracing::ExecutionSpan;
    /// fn example() -> Result<(), Box<dyn std::error::Error>> {
    ///     let span = ExecutionSpan::new("execution", "exec-123");
    ///     // ... error occurs ...
    ///     span.end_error("Out of memory");
    ///     Ok(())
    /// }
    /// ```
    pub fn end_error(mut self, error_message: &str) {
        let duration = self.duration_ms();
        self.span
            .set_attribute(KeyValue::new("duration_ms", duration as i64));
        self.span
            .set_attribute(KeyValue::new("error.message", error_message.to_string()));
        self.span
            .set_status(Status::error(error_message.to_string()));
        self.span.end();

        eprintln!(
            "[TRACE] Span '{}' failed after {}ms: {} (execution_id: {})",
            self.name, duration, error_message, self.execution_id
        );
    }
}

/// Auto-closing span guard (RAII pattern)
/// Automatically ends the span when dropped
///
/// # SECURITY FIX: Properly tracks error state
/// Previously, SpanGuard always ended as success even on errors.
/// Now it correctly ends as error if set_error() was called.
///
/// # Example
/// ```rust
/// {
///     use worker::tracing::SpanGuard;
///     let _guard = SpanGuard::new("operation", "exec-123");
/// } // Span automatically closed with correct status
/// ```
pub struct SpanGuard {
    span: Option<ExecutionSpan>,
    error_message: Option<String>,
}

#[allow(dead_code)]
impl SpanGuard {
    /// Create a new span guard
    pub fn new(name: &str, execution_id: &str) -> Self {
        Self {
            span: Some(ExecutionSpan::new(name, execution_id)),
            error_message: None,
        }
    }

    /// Get mutable reference to the span
    /// SECURITY: Replaced unwrap() with proper error handling
    pub fn span_mut(&mut self) -> Option<&mut ExecutionSpan> {
        self.span.as_mut()
    }

    /// Mark the span as failed
    /// This will cause Drop to end the span with an error status
    pub fn set_error(&mut self, error: &str) {
        self.error_message = Some(error.to_string());
        if let Some(span) = self.span.as_mut() {
            span.set_attribute("error", error);
        }
    }

    /// Manually end the span successfully
    /// Consumes the guard to prevent double-ending
    pub fn end_success(mut self) {
        if let Some(span) = self.span.take() {
            span.end_success();
        }
    }

    /// Manually end the span with error
    /// Consumes the guard to prevent double-ending
    pub fn end_error(mut self, error: &str) {
        if let Some(span) = self.span.take() {
            span.end_error(error);
        }
    }
}

impl Drop for SpanGuard {
    fn drop(&mut self) {
        if let Some(span) = self.span.take() {
            // SECURITY FIX: Check error state and end appropriately
            if let Some(error_msg) = &self.error_message {
                span.end_error(error_msg);
            } else {
                span.end_success();
            }
        }
    }
}

/// Helper to extract trace context from headers
/// Used for distributed tracing across HTTP boundaries
///
/// # Example
/// ```rust
/// use worker::tracing::{extract_trace_id, ExecutionSpan};
///
/// fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let headers = vec![
///         ("traceparent".to_string(), "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string()),
///     ];
///     let trace_id = extract_trace_id(&headers).ok_or("missing trace")?;
///     let _span = ExecutionSpan::new("downstream", &trace_id);
///     Ok(())
/// }
/// ```
#[allow(dead_code)]
pub fn extract_trace_id(headers: &[(String, String)]) -> Option<String> {
    // Look for standard trace headers
    for (key, value) in headers {
        let key_lower = key.to_lowercase();
        if key_lower == "traceparent" || key_lower == "x-trace-id" {
            return Some(value.clone());
        }
    }
    None
}

/// Create trace context for propagation
/// Returns headers to inject into outgoing requests
///
/// # Example
/// ```rust
/// use worker::tracing::{ExecutionSpan, create_trace_context};
///
/// fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let span = ExecutionSpan::new("execution", "exec-123");
///     let _headers = create_trace_context(&span);
///     Ok(())
/// }
/// ```
#[allow(dead_code)]
pub fn create_trace_context(span: &ExecutionSpan) -> Vec<(String, String)> {
    vec![
        ("x-trace-id".to_string(), span.execution_id.clone()),
        ("x-span-name".to_string(), span.name.clone()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_span_creation() {
        let span = ExecutionSpan::new("test-span", "test-123");
        assert_eq!(span.name, "test-span");
        assert_eq!(span.execution_id, "test-123");
    }

    #[test]
    fn test_span_duration() {
        let span = ExecutionSpan::new("test", "123");
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(span.duration_ms() >= 10);
    }

    #[test]
    fn test_span_guard() {
        {
            let mut guard = SpanGuard::new("test", "123");
            guard.span_mut().unwrap().set_attribute("test", "value");
        } // Span automatically closed
    }

    #[test]
    fn test_trace_context_extraction() {
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-trace-id".to_string(), "trace-123".to_string()),
        ];

        let trace_id = extract_trace_id(&headers);
        assert_eq!(trace_id, Some("trace-123".to_string()));
    }
}
