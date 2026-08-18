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
/// use talos_trace::{init_tracing, ExecutionSpan};
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
use std::sync::OnceLock;
use std::time::Instant;

/// Retains the SDK tracer provider so `shutdown_tracing` can flush + shut it
/// down. otel 0.28+ removed `global::shutdown_tracer_provider`, so the handle
/// must be kept explicitly. Set once at `init_tracing`.
static TRACER_PROVIDER: OnceLock<opentelemetry_sdk::trace::SdkTracerProvider> = OnceLock::new();

/// Resolve the trace [`Sampler`] from the standard OpenTelemetry environment
/// variables `OTEL_TRACES_SAMPLER` and `OTEL_TRACES_SAMPLER_ARG`, falling back to
/// the SDK default (`parentbased_always_on`) when unset — so leaving them unset
/// preserves the prior always-sample behaviour exactly.
///
/// [`Sampler`]: opentelemetry_sdk::trace::Sampler
fn sampler_from_env() -> opentelemetry_sdk::trace::Sampler {
    parse_sampler(
        std::env::var("OTEL_TRACES_SAMPLER").ok().as_deref(),
        std::env::var("OTEL_TRACES_SAMPLER_ARG").ok().as_deref(),
    )
}

/// Pure mapping from the OTEL sampler env values to a [`Sampler`], factored out
/// so it can be unit-tested without touching process env. Recognises the spec
/// sampler names; the `*_traceidratio` variants read `arg` as a ratio in `[0, 1]`
/// (clamped; defaults to `1.0` if missing/unparseable). An unrecognised
/// `OTEL_TRACES_SAMPLER` falls back to the default with a stderr warning so an
/// operator typo is visible rather than silently sampling everything.
///
/// [`Sampler`]: opentelemetry_sdk::trace::Sampler
fn parse_sampler(kind: Option<&str>, arg: Option<&str>) -> opentelemetry_sdk::trace::Sampler {
    use opentelemetry_sdk::trace::Sampler;
    let ratio = || {
        arg.and_then(|s| s.trim().parse::<f64>().ok())
            .map(|r| r.clamp(0.0, 1.0))
            .unwrap_or(1.0)
    };
    match kind.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        None | Some("parentbased_always_on") => Sampler::ParentBased(Box::new(Sampler::AlwaysOn)),
        Some("always_on") => Sampler::AlwaysOn,
        Some("always_off") => Sampler::AlwaysOff,
        Some("traceidratio") => Sampler::TraceIdRatioBased(ratio()),
        Some("parentbased_always_off") => Sampler::ParentBased(Box::new(Sampler::AlwaysOff)),
        Some("parentbased_traceidratio") => {
            Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(ratio())))
        }
        Some(other) => {
            eprintln!(
                "[TRACING] unrecognised OTEL_TRACES_SAMPLER='{other}'; using parentbased_always_on"
            );
            Sampler::ParentBased(Box::new(Sampler::AlwaysOn))
        }
    }
}

/// Environment variables consulted for the OTLP trace endpoint, in precedence
/// order (first non-empty wins). See [`endpoint_from_env`].
///
/// `JAEGER_ENDPOINT` is deliberately FIRST and is not going away: it is the name
/// this codebase has always used and an operator may have it set out-of-band.
/// The two `OTEL_EXPORTER_OTLP_*` names are the OpenTelemetry spec's, added
/// because every collector/sidecar chart sets them by default and because this
/// crate already reads the spec's `OTEL_TRACES_SAMPLER*` — the configuration
/// surface was half-standard already.
pub const TRACE_ENDPOINT_ENV_VARS: [&str; 3] = [
    "JAEGER_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
];

/// Resolve the OTLP trace endpoint from the environment, or `None` when the
/// operator has configured no endpoint at all.
///
/// **`None` means DISABLED, and that is the whole point of this function.**
/// Both binaries previously did
/// `env::var("JAEGER_ENDPOINT").ok().or_else(|| Some("http://localhost:4317"))`,
/// which substituted a default for the unset case and so made [`init_tracing`]'s
/// documented "no endpoint ⇒ tracing disabled" path *unreachable*. Inside a
/// container `localhost:4317` is the process itself, so every unconfigured
/// deployment — the dev stack and every Helm install, neither of which sets the
/// variable — built a batch span processor that failed every export and logged
/// an ERROR per flush, indefinitely.
///
/// This is also why the endpoint is resolved HERE rather than by letting
/// `opentelemetry-otlp` read the env itself: that crate's own chain
/// (`exporter/tonic/mod.rs::resolve_endpoint`) ends in
/// `OTEL_EXPORTER_OTLP_GRPC_ENDPOINT_DEFAULT` — the identical
/// `http://localhost:4317` — so "just let the SDK read the standard vars" would
/// reproduce this exact bug one layer down, where the `None` path can no longer
/// see it.
#[must_use]
pub fn endpoint_from_env() -> Option<String> {
    let values: Vec<Option<String>> = TRACE_ENDPOINT_ENV_VARS
        .iter()
        .map(|k| std::env::var(k).ok())
        .collect();
    first_configured(values.iter().map(Option::as_deref))
}

/// Pure core of [`endpoint_from_env`]: the first candidate that is present and
/// non-empty after trimming, else `None`. Factored out so the precedence and the
/// "unset ⇒ `None`" invariant are unit-testable without touching process env
/// (the same pattern as `parse_sampler` above).
///
/// An explicitly EMPTY variable (`JAEGER_ENDPOINT=`) is treated as unset and
/// falls through: a blank value is how compose/Helm spell "not configured", and
/// handing `""` to the exporter builder is an invalid-URI error, not a disable.
fn first_configured<'a>(candidates: impl IntoIterator<Item = Option<&'a str>>) -> Option<String> {
    candidates
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Render an OTLP endpoint for logging with anything credential-bearing removed:
/// keeps scheme + host + port, drops URL userinfo, path, query and fragment
/// (replacing them with `/…` when present, so the reader can see that something
/// was elided rather than that the endpoint had no path).
///
/// Hosted OTLP collectors routinely carry an ingest key in the userinfo or the
/// query string, and this endpoint is printed at startup by both binaries — so
/// printing it verbatim is a credential-into-logs path the moment anyone points
/// Talos at a SaaS backend. Deliberately hand-rolled: `talos-trace` has no URL
/// dependency and this does not warrant adding one.
#[must_use]
pub fn redact_endpoint(endpoint: &str) -> String {
    let raw = endpoint.trim();
    let (scheme, rest) = match raw.split_once("://") {
        Some((s, r)) => (Some(s), r),
        None => (None, raw),
    };
    // Everything from the first `/`, `?` or `#` onward is path/query/fragment.
    let (authority, tail) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    // Drop userinfo (`user:password@host`) entirely, flagging that it was there.
    // `rsplit_once` so a `:` or `@` inside the userinfo can't shift the split.
    let (had_userinfo, host) = match authority.rsplit_once('@') {
        Some((_, h)) => (true, h),
        None => (false, authority),
    };
    let mut out = String::new();
    if let Some(s) = scheme {
        out.push_str(s);
        out.push_str("://");
    }
    if had_userinfo {
        out.push_str("<redacted>@");
    }
    out.push_str(host);
    if !tail.is_empty() {
        out.push_str("/…");
    }
    out
}

/// Initialize OpenTelemetry tracing
/// Sets up the global tracer provider with OTLP exporter (for Jaeger)
///
/// # Arguments
/// * `service_name` - Name of the service (e.g., "talos-worker")
/// * `endpoint` - OTLP gRPC endpoint (e.g., "http://jaeger:4317"). `None`
///   disables tracing entirely: no exporter is built, no span is ever queued and
///   no export is ever attempted. Callers MUST obtain this from
///   [`endpoint_from_env`] rather than substituting a default of their own.
///
/// # Example
/// ```rust
/// // Send traces to Jaeger via OTLP
/// use talos_trace::init_tracing;
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

    // Redacted: the endpoint can carry an ingest credential (see
    // `redact_endpoint`). Logged once, not twice — the old code printed it at
    // init AND again on success.
    let shown = redact_endpoint(endpoint);
    println!(
        "[TRACING] Initializing OpenTelemetry for service: {}",
        service_name
    );
    println!("[TRACING] OTLP endpoint: {}", shown);

    // Build tracer provider with OTLP exporter
    use opentelemetry_otlp::SpanExporter;
    use opentelemetry_sdk::trace::SdkTracerProvider;

    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    // Sampler from the standard OTEL env vars (default = parentbased_always_on,
    // the SDK default and prior behaviour). This is the production knob for
    // bounding span volume on the worker's hot path, e.g.
    // `OTEL_TRACES_SAMPLER=parentbased_traceidratio OTEL_TRACES_SAMPLER_ARG=0.1`.
    let sampler = sampler_from_env();

    // otel 0.28+: the batch span processor is runtime-agnostic (dedicated
    // background thread), so `with_batch_exporter` no longer takes a runtime
    // argument; `Resource` is built via the builder (`Resource::new` was removed).
    let tracer_provider = SdkTracerProvider::builder()
        .with_sampler(sampler)
        .with_batch_exporter(exporter)
        .with_resource(
            Resource::builder()
                .with_attributes(vec![
                    KeyValue::new("service.name", service_name.to_string()),
                    KeyValue::new("service.version", env!("CARGO_PKG_VERSION").to_string()),
                ])
                .build(),
        )
        .build();

    // Set as global tracer provider, retaining a handle so `shutdown_tracing`
    // can flush + shut it down (otel 0.28+ removed `global::shutdown_tracer_provider`).
    let _ = TRACER_PROVIDER.set(tracer_provider.clone());
    global::set_tracer_provider(tracer_provider);

    // Install the W3C TraceContext propagator. Without a registered propagator
    // the global default is a NO-OP, so `talos_trace_nats::inject_trace_context`
    // / `extract_trace_context` silently serialise/parse nothing and every
    // cross-process (NATS) trace link is dropped. Installing it here means both
    // binaries that call `init_tracing` (controller + worker) propagate the same
    // `traceparent` wire format. Done after `set_tracer_provider` so the whole
    // tracing stack is live in one place.
    global::set_text_map_propagator(opentelemetry_sdk::propagation::TraceContextPropagator::new());

    // NOTE the wording: the exporter is BUILT, and `connect_lazy` means nothing
    // has been dialled yet. This line asserts that the pipeline was constructed,
    // NOT that a single span has ever arrived — the pre-fix stack printed this
    // exact ✅ for thirty-six hours while delivering nothing. Whether spans land
    // is answerable only at the backend.
    println!("[TRACING] ✅ OpenTelemetry span exporter built (delivery unverified)");
    println!("[TRACING] Traces will be exported to: {}", shown);

    Ok(())
}

/// A concrete SDK tracer from the globally-installed provider, suitable for
/// building a `tracing_opentelemetry` layer via `.with_tracer(...)`.
///
/// Returns `None` if [`init_tracing`] has not installed a provider (e.g. no OTLP
/// endpoint configured). This accessor exists because the bridge layer requires
/// a tracer implementing `PreSampledTracer` — the concrete
/// `opentelemetry_sdk::trace::Tracer` does, but the boxed tracer returned by
/// `opentelemetry::global::tracer_provider().tracer(..)` does not.
#[must_use]
pub fn sdk_tracer(scope: &'static str) -> Option<opentelemetry_sdk::trace::Tracer> {
    use opentelemetry::trace::TracerProvider as _;
    TRACER_PROVIDER.get().map(|provider| provider.tracer(scope))
}

/// Shutdown tracing gracefully
/// Call this before application exit to flush remaining traces
pub fn shutdown_tracing() {
    println!("[TRACING] Shutting down tracing, flushing remaining spans...");
    if let Some(provider) = TRACER_PROVIDER.get() {
        if let Err(e) = provider.shutdown() {
            eprintln!("[TRACING] shutdown error while flushing spans: {e}");
        }
    }
    println!("[TRACING] ✅ Tracing shutdown complete");
}

/// Upper bound, in Unicode scalar values, on any caller-supplied string this
/// crate writes to a span or to the process's stdout/stderr.
///
/// Matches `talos_worker_runtime::error_sanitize::sanitize_error_message`'s
/// bound so the two agree. Before this existed, `end_error` had **no** bound at
/// all and its one guest-text caller passes a WASM-authored string of arbitrary
/// length.
pub const MAX_SPAN_TEXT_CHARS: usize = 2000;

/// Redact, then bound, a caller-supplied string before it reaches a span
/// attribute, a span status, or one of this module's `println!`/`eprintln!`
/// lines.
///
/// # Why this lives at the sink and not at the call sites
///
/// Callers of [`ExecutionSpan`] hand it error text that originates in untrusted
/// WASM guest code. A module that echoes an upstream `401` routinely carries an
/// `sk-*` / `ghp_*` / `Bearer …` value inside that text. Before this function
/// existed, whether the secret was scrubbed depended on which caller you were:
/// `talos-worker-runtime`'s `runtime.rs` wrapped its argument in
/// `talos_dlp_provider::redact_str` (PR #433) while `worker/src/main.rs` passed
/// the output of `sanitize_error_message`, which strips paths, line numbers and
/// internal IPs and does **no** secret redaction at all. Two sinks, the same
/// untrusted input, opposite treatment.
///
/// Repairing the individual call sites would leave the next caller free to make
/// the same choice again. Redaction therefore happens **here**, on the sink
/// side, where no caller can opt out. Callers that redact anyway are harmless:
/// redaction is idempotent (pinned by `redaction_is_idempotent`).
///
/// # Order of operations
///
/// Redact FIRST, truncate SECOND. The reverse order can cut a token across the
/// bound so no pattern matches it any more, and an unredacted prefix survives.
///
/// # Failure behaviour
///
/// [`talos_dlp_provider::redact_str_failsafe`] converts a panic inside the
/// redactor into [`talos_dlp_provider::REDACTION_UNAVAILABLE`]. There is no
/// path through this function that returns the caller's bytes unredacted.
///
/// # Cost
///
/// The `regex` crate is a finite-automaton engine with no backtracking, so
/// matching is linear in the input length with no catastrophic-backtracking
/// case; a pathological 2000-character input costs one combined-automaton pass
/// (plus one Luhn-gated card scan) and, only when something actually matches,
/// one replacement walk. On the common no-match input the result borrows and
/// nothing is allocated. These sinks are per-job, not per-instruction.
#[must_use]
pub fn redact_span_text(raw: &str) -> std::borrow::Cow<'_, str> {
    let redacted = talos_dlp_provider::redact_str_failsafe(raw);
    if redacted.chars().count() <= MAX_SPAN_TEXT_CHARS {
        return redacted;
    }
    let truncated: String = redacted.chars().take(MAX_SPAN_TEXT_CHARS).collect();
    std::borrow::Cow::Owned(format!("{truncated}... [truncated]"))
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
    /// use talos_trace::ExecutionSpan;
    /// let span = ExecutionSpan::new("workflow-step", "exec-123");
    /// ```
    pub fn new(name: &str, execution_id: &str) -> Self {
        // A fresh root span (parent taken from the thread-local context, which
        // is empty in the worker's per-job task — so effectively a root).
        Self::build(name, execution_id, None)
    }

    /// Build the underlying span, optionally as a child of a propagated parent
    /// trace context. When `parent` is `Some`, the span is started with
    /// `start_with_context` so it inherits the parent's `trace_id` and links to
    /// its `span_id` — this is what stitches the worker's execution span into the
    /// controller's distributed trace across the NATS job boundary.
    fn build(name: &str, execution_id: &str, parent: Option<&opentelemetry::Context>) -> Self {
        let provider = global::tracer_provider();
        let tracer = provider.tracer("talos-wasm-runtime");

        let builder = tracer
            .span_builder(name.to_string())
            .with_kind(SpanKind::Internal);
        let mut span = match parent {
            Some(cx) => builder.start_with_context(&tracer, cx),
            None => builder.start(&tracer),
        };

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
    /// use talos_trace::ExecutionSpan;
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
    /// use talos_trace::ExecutionSpan;
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
        // Sink-side redaction: see `redact_span_text`. Every string a caller
        // can put on this span goes through it, including keys that are not
        // named "error" — `worker/src/main.rs` stamps guest error text under
        // the key `"error"` on its sibling span type, and nothing stops a
        // future caller picking any other key.
        self.span.set_attribute(KeyValue::new(
            key.to_string(),
            redact_span_text(value).into_owned(),
        ));
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
    /// use talos_trace::ExecutionSpan;
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
        // The event NAME is a sink too — an error string used as an event name
        // would otherwise bypass every other guard here.
        self.span
            .add_event(redact_span_text(name).into_owned(), vec![]);
    }

    /// Record an event with attributes
    ///
    /// # Example
    /// ```rust
    /// use talos_trace::ExecutionSpan;
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
            .map(|(k, v)| KeyValue::new(k.to_string(), redact_span_text(v).into_owned()))
            .collect();

        self.span
            .add_event(redact_span_text(name).into_owned(), attrs);
    }

    /// Get the execution duration so far
    pub fn duration_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }

    /// End the span successfully
    ///
    /// # Example
    /// ```rust
    /// use talos_trace::ExecutionSpan;
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
    /// use talos_trace::ExecutionSpan;
    /// fn example() -> Result<(), Box<dyn std::error::Error>> {
    ///     let span = ExecutionSpan::new("execution", "exec-123");
    ///     // ... error occurs ...
    ///     span.end_error("Out of memory");
    ///     Ok(())
    /// }
    /// ```
    pub fn end_error(mut self, error_message: &str) {
        // SECURITY CHOKEPOINT. `error_message` is untrusted: it reaches here
        // from WASM guest output. Redact ONCE, then use the redacted value for
        // all three writes below.
        //
        // Two of those three sinks are export-gated (the attribute and the
        // status only leave the process when an OTLP endpoint is configured),
        // but the `eprintln!` is NOT — it runs on every call regardless of
        // whether tracing is enabled. Its success twin in `end_success` is
        // observable in the running dev stack's worker log today, which is the
        // positive evidence that this line is live rather than dormant.
        //
        // Deliberately NOT calling `redact_span_text` separately per sink: one
        // call, one value, no way for the three to disagree.
        let safe = redact_span_text(error_message);
        let duration = self.duration_ms();
        self.span
            .set_attribute(KeyValue::new("duration_ms", duration as i64));
        self.span
            .set_attribute(KeyValue::new("error.message", safe.to_string()));
        self.span.set_status(Status::error(safe.to_string()));
        self.span.end();

        eprintln!(
            "[TRACE] Span '{}' failed after {}ms: {} (execution_id: {})",
            self.name, duration, safe, self.execution_id
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
///     use talos_trace::SpanGuard;
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
        // Sibling sink taking caller-supplied error text. `span.set_attribute`
        // redacts on the way in, and the stored copy is redacted here so the
        // `Drop`/`end_error` path cannot re-introduce the raw string.
        self.error_message = Some(redact_span_text(error).into_owned());
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
/// use talos_trace::{extract_trace_id, ExecutionSpan};
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
/// use talos_trace::{ExecutionSpan, create_trace_context};
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

impl ExecutionSpan {
    /// Create a span that continues a propagated parent trace context.
    ///
    /// The worker's NATS job/pipeline subscribers extract the W3C trace context
    /// from inbound message headers (`talos_trace_nats::extract_trace_context`)
    /// and pass it here. The span is started as a child of that context so the
    /// worker's `job-execution` / `pipeline-execution` span shares the
    /// originating controller trace's `trace_id` and links to its parent span,
    /// instead of appearing as a disconnected root in the trace backend.
    pub fn new_with_parent(name: &str, execution_id: &str, cx: &opentelemetry::Context) -> Self {
        Self::build(name, execution_id, Some(cx))
    }
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

    /// Regression test for the distributed-tracing link across the NATS job
    /// boundary: `new_with_parent` must start its span as a CHILD of the
    /// propagated context so it inherits the parent `trace_id`. Previously the
    /// context was discarded and the worker's job span became a disconnected
    /// root in the trace backend.
    #[test]
    fn new_with_parent_inherits_parent_trace_id() {
        use opentelemetry::trace::{
            Span, SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState,
        };
        use opentelemetry::Context;

        // A concrete SDK provider is required — the global no-op tracer yields
        // an all-zero span context, so parent propagation is only observable
        // against a real provider.
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        global::set_tracer_provider(provider);

        let parent_trace_id = TraceId::from_hex("0af7651916cd43dd8448eb211c80319c").unwrap();
        let parent_sc = SpanContext::new(
            parent_trace_id,
            SpanId::from_hex("b7ad6b7169203331").unwrap(),
            TraceFlags::SAMPLED,
            true, // remote (as produced by the W3C propagator extractor)
            TraceState::default(),
        );
        let parent_cx = Context::new().with_remote_span_context(parent_sc);

        let child = ExecutionSpan::new_with_parent("job-execution", "exec-1", &parent_cx);
        assert_eq!(
            child.span.span_context().trace_id(),
            parent_trace_id,
            "new_with_parent must inherit the propagated parent trace_id"
        );

        // A fresh root span must NOT share the parent trace_id.
        let root = ExecutionSpan::new("root", "exec-2");
        assert_ne!(
            root.span.span_context().trace_id(),
            parent_trace_id,
            "a root span must not inherit an unrelated trace_id"
        );
    }

    #[test]
    fn parse_sampler_defaults_to_parentbased_always_on() {
        // Unset env preserves the prior always-sample behaviour exactly.
        let s = format!("{:?}", parse_sampler(None, None));
        assert!(
            s.contains("ParentBased"),
            "default should be ParentBased: {s}"
        );
        assert!(
            s.contains("AlwaysOn"),
            "default inner should be AlwaysOn: {s}"
        );
    }

    #[test]
    fn parse_sampler_recognises_spec_names() {
        assert!(format!("{:?}", parse_sampler(Some("always_off"), None)).contains("AlwaysOff"));
        assert!(format!("{:?}", parse_sampler(Some("always_on"), None)).contains("AlwaysOn"));

        let ratio = format!("{:?}", parse_sampler(Some("traceidratio"), Some("0.25")));
        assert!(ratio.contains("TraceIdRatioBased"), "{ratio}");
        assert!(
            ratio.contains("0.25"),
            "ratio arg must be honoured: {ratio}"
        );

        let pbr = format!(
            "{:?}",
            parse_sampler(Some("parentbased_traceidratio"), Some("0.1"))
        );
        assert!(
            pbr.contains("ParentBased") && pbr.contains("TraceIdRatioBased") && pbr.contains("0.1"),
            "{pbr}"
        );
    }

    #[test]
    fn parse_sampler_clamps_ratio_and_handles_bad_input() {
        // Out-of-range ratios clamp to [0, 1].
        assert!(format!("{:?}", parse_sampler(Some("traceidratio"), Some("5.0"))).contains("1.0"));
        assert!(format!("{:?}", parse_sampler(Some("traceidratio"), Some("-1"))).contains("0.0"));
        // Unparseable arg → default ratio 1.0.
        assert!(format!("{:?}", parse_sampler(Some("traceidratio"), Some("abc"))).contains("1.0"));
        // Case-insensitive.
        assert!(format!("{:?}", parse_sampler(Some("ALWAYS_OFF"), None)).contains("AlwaysOff"));
        // Unknown sampler name → safe default (NOT always-off, NOT a panic).
        let unk = format!("{:?}", parse_sampler(Some("bogus"), None));
        assert!(
            unk.contains("ParentBased") && unk.contains("AlwaysOn"),
            "{unk}"
        );
    }

    // ---------------------------------------------------------------------
    // Endpoint resolution — the invariant this whole change exists to restore.
    // ---------------------------------------------------------------------

    /// THE regression test. Nothing configured must resolve to `None`, because
    /// `None` is what makes `init_tracing` take its disabled path and build no
    /// exporter at all. The pre-fix call sites answered `Some("http://localhost:4317")`
    /// here, which is why both binaries exported to nowhere, loudly, forever.
    #[test]
    fn nothing_configured_resolves_to_none_not_a_default() {
        assert_eq!(first_configured([None, None, None]), None);
        // An explicitly empty value is "not configured", not an endpoint.
        assert_eq!(first_configured([Some(""), Some("   "), None]), None);
    }

    #[test]
    fn jaeger_endpoint_wins_and_standard_vars_are_honoured() {
        // 1. JAEGER_ENDPOINT first — an operator who set it out-of-band is
        //    unaffected by the addition of the standard names.
        assert_eq!(
            first_configured([
                Some("http://jaeger:4317"),
                Some("http://traces:4317"),
                Some("http://generic:4317")
            ])
            .as_deref(),
            Some("http://jaeger:4317")
        );
        // 2. signal-specific next.
        assert_eq!(
            first_configured([
                None,
                Some("http://traces:4317"),
                Some("http://generic:4317")
            ])
            .as_deref(),
            Some("http://traces:4317")
        );
        // 3. generic last.
        assert_eq!(
            first_configured([None, None, Some("http://generic:4317")]).as_deref(),
            Some("http://generic:4317")
        );
        // An empty higher-precedence var falls THROUGH rather than disabling a
        // lower one that is genuinely set.
        assert_eq!(
            first_configured([Some(""), None, Some("http://generic:4317")]).as_deref(),
            Some("http://generic:4317")
        );
        // Surrounding whitespace is trimmed (compose/Helm YAML folding).
        assert_eq!(
            first_configured([Some("  http://jaeger:4317 ")]).as_deref(),
            Some("http://jaeger:4317")
        );
    }

    /// The env-reading wrapper must agree with the pure core on the case that
    /// matters. Asserted only for the "nothing set" direction and only after
    /// removing the vars, because process env is global and other tests in the
    /// binary could otherwise race a `set_var`.
    #[test]
    fn endpoint_from_env_lists_exactly_the_documented_vars() {
        assert_eq!(
            TRACE_ENDPOINT_ENV_VARS,
            [
                "JAEGER_ENDPOINT",
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                "OTEL_EXPORTER_OTLP_ENDPOINT",
            ]
        );
    }

    #[test]
    fn redact_endpoint_keeps_host_and_drops_credentials() {
        // The ordinary case is unchanged and still readable.
        assert_eq!(redact_endpoint("http://jaeger:4317"), "http://jaeger:4317");
        assert_eq!(
            redact_endpoint("http://localhost:4317"),
            "http://localhost:4317"
        );
        // Userinfo — the hosted-collector credential form — is removed, and the
        // fact that it was there is preserved.
        assert_eq!(
            redact_endpoint("https://ingestkey:s3cret@otlp.example.com:443"),
            "https://<redacted>@otlp.example.com:443"
        );
        // Query string and path are elided but flagged.
        assert_eq!(
            redact_endpoint("https://otlp.example.com/v1/traces?api-key=abc123"),
            "https://otlp.example.com/…"
        );
        assert_eq!(
            redact_endpoint("https://otlp.example.com?token=abc"),
            "https://otlp.example.com/…"
        );
        // No secret substring survives, which is the property that matters.
        for raw in [
            "https://user:s3cret@otlp.example.com/v1/traces?api-key=abc123#frag",
            "https://otlp.example.com/v1/traces/abc123",
        ] {
            let out = redact_endpoint(raw);
            assert!(!out.contains("s3cret"), "{out}");
            assert!(!out.contains("abc123"), "{out}");
        }
        // Schemeless and empty inputs must not panic.
        assert_eq!(redact_endpoint("jaeger:4317"), "jaeger:4317");
        assert_eq!(redact_endpoint(""), "");
    }
}

// ============================================================================
// Sink-level redaction tests (D4)
// ============================================================================
//
// These drive the REAL sinks — `ExecutionSpan::end_error`'s exported span and
// its `eprintln!` line — and assert on the bytes those sinks actually emitted.
// Nothing here re-implements the redactor: every expectation is "the fixture
// secret must not appear in the emitted text", which is false for ANY redactor
// that does nothing, including a hand-rolled one that misses a pattern.
#[cfg(test)]
mod span_sink_redaction_tests {
    use super::*;

    /// Obviously-fake fixtures. Every one is constructed to match a specific
    /// arm of `talos_dlp_provider::PATTERN_SPECS`; none is a real credential.
    /// `AKIAIOSFODNN7EXAMPLE` is AWS's own published documentation example.
    const FIXTURES: &[(&str, &str)] = &[
        ("openai_style", "sk-TESTONLYabcdefghijklmnop"),
        ("github_pat", "ghp_TESTONLYabcdefghijklmnop"),
        ("bearer", "Bearer TESTONLYabcdefghijklmnop"),
        ("aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
        (
            "jwt",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJURVNUT05MWSJ9.c2lnVEVTVE9OTFk",
        ),
    ];

    /// The distinctive substring of each fixture that must never survive.
    /// For `Bearer …` the word "Bearer" itself is not secret — the token is.
    fn secret_part(fixture: &str) -> &str {
        fixture.strip_prefix("Bearer ").unwrap_or(fixture)
    }

    /// Shape of the real thing: `worker/src/main.rs` builds
    /// `format!("execution failure: {e}")` where `e` is guest text.
    fn guest_error(fixture: &str) -> String {
        format!("execution failure: upstream returned 401 for {fixture}")
    }

    // ------------------------------------------------------------------
    // Sink 1 — the exported span (`error.message` attribute + status).
    // ------------------------------------------------------------------

    /// Install a real SDK tracer provider backed by an in-memory exporter, so
    /// the assertions read what `ExecutionSpan` genuinely emitted rather than
    /// what we believe it emitted. Global provider state is process-wide, so
    /// this is installed exactly once per test binary.
    /// A process-unique execution id, so a test can pick ITS OWN spans out of
    /// the shared in-memory exporter. The exporter is global (the provider is
    /// process-wide) and libtest runs these tests in parallel with the other
    /// span-creating tests in this crate, so neither `reset()` nor a
    /// `spans.len() == 1` assertion is safe here — both would flake.
    fn unique_exec_id(tag: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        format!("exec-{tag}-{}", N.fetch_add(1, Ordering::Relaxed))
    }

    /// The spans this test emitted, identified by their `execution.id`.
    fn spans_for(
        exp: &opentelemetry_sdk::trace::InMemorySpanExporter,
        exec_id: &str,
    ) -> Vec<opentelemetry_sdk::trace::SpanData> {
        exp.get_finished_spans()
            .expect("in-memory export failed")
            .into_iter()
            .filter(|s| {
                s.attributes
                    .iter()
                    .any(|kv| kv.key.as_str() == "execution.id" && kv.value.as_str() == exec_id)
            })
            .collect()
    }

    fn exporter() -> &'static opentelemetry_sdk::trace::InMemorySpanExporter {
        static EXPORTER: OnceLock<opentelemetry_sdk::trace::InMemorySpanExporter> = OnceLock::new();
        EXPORTER.get_or_init(|| {
            let exp = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
            let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_simple_exporter(exp.clone())
                .build();
            global::set_tracer_provider(provider);
            exp
        })
    }

    #[test]
    fn exported_span_carries_no_fixture_secret() {
        let exp = exporter();
        for (name, fixture) in FIXTURES {
            let exec_id = unique_exec_id("end-error");
            let span = ExecutionSpan::new("wasm-execution", &exec_id);
            span.end_error(&guest_error(fixture));

            let spans = spans_for(exp, &exec_id);
            assert_eq!(spans.len(), 1, "{name}: expected exactly one exported span");
            let emitted = &spans[0];

            // The `error.message` attribute, as actually exported.
            let attr = emitted
                .attributes
                .iter()
                .find(|kv| kv.key.as_str() == "error.message")
                .map(|kv| kv.value.as_str().into_owned())
                .unwrap_or_else(|| panic!("{name}: no error.message attribute on the span"));
            assert!(
                !attr.contains(secret_part(fixture)),
                "{name}: secret survived into the exported error.message attribute: {attr}"
            );
            assert!(
                attr.contains("[REDACTED:"),
                "{name}: attribute shows no redaction tag: {attr}"
            );

            // The span STATUS description — the third write in `end_error`,
            // and the one a collector surfaces as the error text.
            let status = format!("{:?}", emitted.status);
            assert!(
                !status.contains(secret_part(fixture)),
                "{name}: secret survived into the exported span status: {status}"
            );
        }
    }

    #[test]
    fn exported_attributes_and_event_names_carry_no_secret() {
        let exp = exporter();
        for (name, fixture) in FIXTURES {
            let exec_id = unique_exec_id("attrs");
            let mut span = ExecutionSpan::new("wasm-execution", &exec_id);
            // A future caller stuffing guest text under a non-"error" key, and
            // an error string used as an EVENT NAME — both are sinks.
            span.set_attribute("module.detail", &guest_error(fixture));
            span.add_event(&guest_error(fixture));
            span.add_event_with_attributes("outcome", vec![("detail", &guest_error(fixture))]);
            span.end_success();

            let spans = spans_for(exp, &exec_id);
            assert_eq!(spans.len(), 1, "{name}: expected exactly one exported span");
            let rendered = format!("{:?}", spans);
            assert!(
                rendered.contains("[REDACTED"),
                "{name}: the sink emitted no redacted text at all: {rendered}"
            );
            assert!(
                !rendered.contains(secret_part(fixture)),
                "{name}: secret survived somewhere in the exported span: {rendered}"
            );
        }
    }

    #[test]
    fn span_guard_drop_path_carries_no_secret() {
        // `SpanGuard` has no production caller today, but it is a sink with the
        // same shape: `set_error` writes an `error` attribute and its `Drop`
        // ends the span with the stored message.
        let exp = exporter();
        for (name, fixture) in FIXTURES {
            let exec_id = unique_exec_id("guard");
            {
                let mut guard = SpanGuard::new("wasm-execution", &exec_id);
                guard.set_error(&guest_error(fixture));
            } // Drop -> end_error

            let spans = spans_for(exp, &exec_id);
            assert_eq!(spans.len(), 1, "{name}: expected exactly one exported span");
            let rendered = format!("{:?}", spans);
            assert!(
                rendered.contains("[REDACTED"),
                "{name}: the sink emitted no redacted text at all: {rendered}"
            );
            assert!(
                !rendered.contains(secret_part(fixture)),
                "{name}: secret survived into the SpanGuard drop path: {rendered}"
            );
        }
    }

    // ------------------------------------------------------------------
    // Sink 2 — the ALWAYS-ON `eprintln!`.
    // ------------------------------------------------------------------
    //
    // `eprintln!` writes to the process's stderr, which cannot be observed from
    // inside the same test thread. The test therefore re-executes THIS test
    // binary as a child process with a marker env var; the child performs the
    // real `end_error` call and exits, and the parent asserts on the child's
    // captured stderr. That is the actual emitted bytes, not a reconstruction.

    const CHILD_MARKER: &str = "TALOS_SPAN_REDACTION_CHILD_FIXTURE";
    const CHILD_TEST_PATH: &str =
        "span_sink_redaction_tests::stderr_sink_carries_no_fixture_secret";

    #[test]
    fn stderr_sink_carries_no_fixture_secret() {
        if let Ok(fixture) = std::env::var(CHILD_MARKER) {
            // CHILD ROLE: emit through the real sink, then exit before libtest
            // can print anything else.
            ExecutionSpan::new("wasm-execution", "exec-child").end_error(&guest_error(&fixture));
            std::process::exit(0);
        }

        // PARENT ROLE.
        let exe = std::env::current_exe().expect("current_exe");
        for (name, fixture) in FIXTURES {
            let out = std::process::Command::new(&exe)
                .arg(CHILD_TEST_PATH)
                .arg("--exact")
                .arg("--nocapture")
                .env(CHILD_MARKER, fixture)
                .output()
                .expect("failed to spawn the child test process");
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

            // Guard against a vacuous pass: if the child never reached the
            // sink there is nothing to assert about.
            assert!(
                stderr.contains("[TRACE] Span 'wasm-execution' failed"),
                "{name}: the child never emitted the span line — stderr was: {stderr:?}"
            );
            assert!(
                !stderr.contains(secret_part(fixture)),
                "{name}: secret survived into the always-on stderr span line: {stderr}"
            );
            assert!(
                stderr.contains("[REDACTED:"),
                "{name}: stderr line shows no redaction tag: {stderr}"
            );
        }
    }

    // ------------------------------------------------------------------
    // Ordering, bounding and idempotence properties of the chokepoint.
    // ------------------------------------------------------------------

    #[test]
    fn redaction_happens_before_truncation() {
        // Place the token so that it STRADDLES the truncation bound. If the
        // sink truncated first, the cut would split the token, no pattern
        // would match the surviving prefix, and that prefix would be emitted.
        // The AWS access-key pattern is `\bA[KS]IA[0-9A-Z]{16}\b` — it needs
        // the WHOLE key. Cut it short and it stops matching entirely, so a
        // truncate-first implementation emits 15 of the key's 20 characters
        // unredacted.
        //
        // A shorter-prefix fixture would NOT prove this. `sk-TESTONLY…` was
        // tried first and the mutation SURVIVED it: the API_KEY pattern only
        // needs `sk-` plus six characters, so even the truncated stub still
        // matched and was redacted. The chosen fixture has to be one whose
        // surviving prefix genuinely fails to match.
        let fixture = "AKIAIOSFODNN7EXAMPLE";
        let leaked_prefix = "AKIAIOSFODNN7EX";
        // Padding is space-separated because the pattern is `\b`-anchored: a
        // token glued to a preceding word character never matches at all,
        // which would make this test pass for the wrong reason.
        let pad_len = MAX_SPAN_TEXT_CHARS - 16;
        let raw = format!("{} {fixture} trailing", "p".repeat(pad_len));
        assert!(
            pad_len + 1 + leaked_prefix.len() == MAX_SPAN_TEXT_CHARS,
            "fixture setup must cut the token at exactly the leaked prefix"
        );
        assert!(
            raw.chars().count() > MAX_SPAN_TEXT_CHARS,
            "fixture setup must exceed the bound"
        );

        let out = redact_span_text(&raw);
        assert!(
            !out.contains(leaked_prefix),
            "an unredacted prefix survived the bound: {out}"
        );
        assert!(!out.contains("AKIA"), "{out}");
        // The tag itself may be clipped by the bound — that is correct and is
        // the whole point: what gets clipped is the REPLACEMENT, never the
        // secret.
        assert!(out.contains("[REDACTED"), "{out}");
    }

    #[test]
    fn output_is_bounded() {
        let raw = "x".repeat(MAX_SPAN_TEXT_CHARS * 3);
        let out = redact_span_text(&raw);
        assert!(out.ends_with("... [truncated]"), "not truncated: {out}");
        assert!(out.chars().count() <= MAX_SPAN_TEXT_CHARS + "... [truncated]".chars().count());
    }

    #[test]
    fn redaction_is_idempotent() {
        // `talos-worker-runtime`'s `runtime.rs` redacts before calling the
        // sink. Double redaction must be a no-op, or that caller would corrupt
        // its own message.
        for (name, fixture) in FIXTURES {
            let once = redact_span_text(&guest_error(fixture)).into_owned();
            let twice = redact_span_text(&once).into_owned();
            assert_eq!(once, twice, "{name}: second pass changed the output");
        }
    }

    #[test]
    fn clean_operator_text_is_left_alone() {
        // Over-redaction is its own defect: these are the real values the live
        // call sites pass (span/attribute constants and a UUID execution id).
        for s in [
            "cache_hit",
            "compilation_started",
            "execution_completed",
            "wasm-execution",
            "e975a305-4907-4a89-9d85-b7ace2fda577",
            "Signature verification failed",
            "Timeout exceeds maximum",
            "execution timed out after 30 seconds",
        ] {
            assert_eq!(redact_span_text(s), s, "over-redacted: {s}");
        }
    }
}
