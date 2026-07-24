//! Per-job tracing-span adapter shared by the job / pipeline
//! executors (`main.rs`) and [`crate::module_fetcher`]. Extracted
//! verbatim from `main.rs`.

/// Per-job span adapter backed by the current `#[::tracing::instrument]` span.
///
/// Presents the same surface the job/pipeline handlers already use
/// (`set_attribute` / `set_attribute_int` / `add_event` / `end_error` /
/// `end_success`) but routes everything through the `tracing` span via
/// [`tracing_opentelemetry::OpenTelemetrySpanExt`], so attributes/events/status
/// flow through the otel bridge layer (and host-function child spans nest under
/// it). This replaces the manual-otel `ExecutionSpan` for the per-job span now
/// that the worker exports `tracing` spans to OTLP; `ExecutionSpan` remains for
/// the standalone `wasm-execution` span in `runtime.rs`.
pub struct JobSpan {
    span: ::tracing::Span,
}

impl JobSpan {
    /// Wrap the current instrument span and link it to the propagated controller
    /// trace context, so the worker job span nests under the controller
    /// `workflow` span rather than starting a fresh root trace.
    pub fn current_with_parent(cx: &opentelemetry::Context) -> Self {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        let span = ::tracing::Span::current();
        // `set_parent` only errors if the context carries no span; ignore — a
        // missing parent simply yields a root job span (e.g. module-bound jobs).
        let _ = span.set_parent(cx.clone());
        Self { span }
    }

    pub fn set_attribute(&mut self, key: &str, value: &str) {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        self.span.set_attribute(key.to_string(), value.to_string());
    }

    pub fn set_attribute_int(&mut self, key: &str, value: i64) {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        self.span.set_attribute(key.to_string(), value);
    }

    pub fn add_event(&mut self, name: &str) {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        self.span.add_event(name.to_string(), Vec::new());
    }

    pub fn end_error(self, message: &str) {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        self.span
            .set_status(opentelemetry::trace::Status::error(message.to_string()));
    }

    pub fn end_success(self) {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        self.span.set_status(opentelemetry::trace::Status::Ok);
    }
}
