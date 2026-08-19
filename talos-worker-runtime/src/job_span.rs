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
        // Sink-side redaction, mirroring `talos_trace::ExecutionSpan`. This is
        // NOT a hypothetical: `worker/src/main.rs` stamps WASM guest error text
        // here under the key `"error"` on the job- and pipeline-failure paths.
        self.span.set_attribute(
            key.to_string(),
            talos_trace::redact_span_text(value).into_owned(),
        );
    }

    pub fn set_attribute_int(&mut self, key: &str, value: i64) {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        self.span.set_attribute(key.to_string(), value);
    }

    pub fn add_event(&mut self, name: &str) {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        self.span
            .add_event(talos_trace::redact_span_text(name).into_owned(), Vec::new());
    }

    pub fn end_error(self, message: &str) {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        // SECURITY CHOKEPOINT — the sibling of
        // `talos_trace::ExecutionSpan::end_error`, and the one the worker's job
        // and pipeline handlers actually call. Both types share ONE redactor
        // (`talos_trace::redact_span_text`) precisely so they cannot drift
        // apart the way they had before this change: `runtime.rs` redacted its
        // `ExecutionSpan` argument while `main.rs` handed this method
        // `sanitize_error_message` output, which carries no secret redaction.
        self.span.set_status(opentelemetry::trace::Status::error(
            talos_trace::redact_span_text(message).into_owned(),
        ));
    }

    pub fn end_success(self) {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        self.span.set_status(opentelemetry::trace::Status::Ok);
    }
}

// ============================================================================
// Sink-level redaction tests (D4)
// ============================================================================
//
// `JobSpan` — not `talos_trace::ExecutionSpan` — is the type
// `worker/src/main.rs` uses on the job and pipeline failure paths, and the one
// that actually receives WASM guest error text today. These tests install a
// real otel bridge layer over an in-memory exporter and assert on the span the
// sink genuinely exported.
#[cfg(test)]
mod job_span_redaction_tests {
    use super::JobSpan;
    use opentelemetry::trace::TracerProvider as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    /// Obviously-fake fixtures, each matching a specific
    /// `talos_dlp_provider::PATTERN_SPECS` arm. `AKIAIOSFODNN7EXAMPLE` is AWS's
    /// own published documentation example.
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

    fn secret_part(fixture: &str) -> &str {
        fixture.strip_prefix("Bearer ").unwrap_or(fixture)
    }

    #[test]
    fn exported_job_span_carries_no_fixture_secret() {
        for (name, fixture) in FIXTURES {
            // The exact shape `worker/src/main.rs` builds from guest output.
            let guest = format!("execution failure: upstream returned 401 for {fixture}");

            let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
            let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_simple_exporter(exporter.clone())
                .build();
            let layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("test"));
            let subscriber = tracing_subscriber::Registry::default().with(layer);

            tracing::subscriber::with_default(subscriber, || {
                let span = tracing::info_span!("wasm-job");
                let _entered = span.enter();
                let mut job_span = JobSpan::current_with_parent(&opentelemetry::Context::new());
                // Both writes `main.rs` performs on the failure path.
                job_span.set_attribute("error", &guest);
                job_span.add_event(&guest);
                job_span.end_error(&guest);
            });

            let spans = exporter
                .get_finished_spans()
                .expect("in-memory export failed");
            assert_eq!(spans.len(), 1, "{name}: expected exactly one exported span");
            let rendered = format!("{:?}", spans[0]);

            // Guard against a vacuous pass — if the sink wrote nothing there
            // would be no secret to find either.
            assert!(
                rendered.contains("[REDACTED"),
                "{name}: the sink emitted no redacted text at all: {rendered}"
            );
            assert!(
                !rendered.contains(secret_part(fixture)),
                "{name}: secret survived into the exported job span: {rendered}"
            );
        }
    }

    /// The guest-log export surface, and the shared bridge layer that closes
    /// it.
    ///
    /// `tracing_opentelemetry` promotes every `tracing` EVENT emitted inside a
    /// span into an exported OTel span event **named with the formatted
    /// message**. Guest log lines go through
    /// `tracing::{warn,error}!("[WASM] {msg}")` (`crate::host::logging`) with
    /// no redaction — a deliberate, commented decision resting on the
    /// three-tier secrets model and on stdout being an operator surface. So a
    /// bridge layer built inline shipped untrusted guest text to the trace
    /// collector as span-event names, and guest logs were only the loudest of
    /// ~418 event callsites in this crate that interpolate untrusted or
    /// upstream-derived text.
    ///
    /// `talos_trace::otel_bridge_layer_with_tracer` — the ONE constructor both
    /// `worker/src/main.rs` and `controller/src/main.rs` call — filters
    /// promoted events out and exports spans only.
    ///
    /// This test has three arms, and the first two are what make the third
    /// meaningful:
    ///
    /// 1. **Control.** An inline `tracing_opentelemetry::layer()` DOES promote
    ///    the event. Without this arm, arm 3 would pass just as happily if the
    ///    event had never been emitted at all.
    /// 2. **Span writes survive the filter.** `Layer::with_filter` wraps the
    ///    bridge in `tracing_subscriber`'s `Filtered`, and every
    ///    `OpenTelemetrySpanExt` call (`set_parent`, `set_attribute`,
    ///    `add_event`, `set_status`) resolves the bridge by `downcast_raw`. If
    ///    `Filtered` did not forward that downcast, all four would silently
    ///    no-op and the entire redacted span surface would vanish — a far worse
    ///    outcome than the leak being fixed. Asserted, not assumed.
    /// 3. **The invariant.** The guest line is absent from the exported span.
    ///
    /// The fixture is AWS-shaped on purpose. `sk-…` is a bad canary for this
    /// family of tests: its pattern needs only `sk-` plus six characters, so a
    /// truncated or partially-processed stub still matches and a broken
    /// implementation still passes. `\bA[KS]IA[0-9A-Z]{16}\b` needs the whole
    /// token.
    #[test]
    fn guest_log_events_are_not_promoted_by_the_shared_bridge_layer() {
        // AWS's own published documentation example key.
        const CANARY: &str = "[WASM] upstream said AKIAIOSFODNN7EXAMPLE was rejected";

        // Arm 1 — control: the unfiltered bridge DOES promote the event, so
        // arm 3 below is testing a real difference rather than an event that
        // was never emitted.
        {
            let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
            let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_simple_exporter(exporter.clone())
                .build();
            let raw = tracing_opentelemetry::layer().with_tracer(provider.tracer("control"));
            let subscriber = tracing_subscriber::Registry::default().with(raw);
            tracing::subscriber::with_default(subscriber, || {
                let span = tracing::info_span!("wasm-job");
                let _entered = span.enter();
                tracing::error!("{CANARY}");
            });
            let spans = exporter
                .get_finished_spans()
                .expect("in-memory export failed");
            assert!(
                spans[0].events.events.iter().any(|e| e.name == CANARY),
                "CONTROL ARM: an inline `tracing_opentelemetry::layer()` no longer \
                 promotes `tracing` events to span events. That is the behaviour \
                 `talos_trace::otel_bridge_layer_with_tracer` exists to neutralise \
                 — re-read whether the filter is still needed before deleting it. \
                 Events seen: {:?}",
                spans[0].events
            );
        }

        // Arms 2 and 3 — the shared constructor, built exactly as both
        // `main.rs` files build it.
        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let layer = talos_trace::otel_bridge_layer_with_tracer(provider.tracer("shared"));
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("wasm-job");
            let _entered = span.enter();
            let mut job_span = JobSpan::current_with_parent(&opentelemetry::Context::new());
            job_span.set_attribute("error", "deliberate-span-attribute");
            job_span.add_event("deliberate-span-event");
            // The guest log line, emitted exactly as `host::logging` emits it.
            tracing::error!("{CANARY}");
            job_span.end_error("deliberate-span-status");
        });

        let spans = exporter
            .get_finished_spans()
            .expect("in-memory export failed");
        assert_eq!(spans.len(), 1, "expected exactly one exported span");
        let span = &spans[0];
        let events: Vec<String> = span
            .events
            .events
            .iter()
            .map(|e| e.name.to_string())
            .collect();
        let attrs = format!("{:?}", span.attributes);
        let status = format!("{:?}", span.status);

        // Arm 2 — the deliberate, already-redacted span surface still lands.
        // If `Filtered` stopped forwarding `downcast_raw`, all three of these
        // would silently become no-ops.
        assert!(
            attrs.contains("deliberate-span-attribute"),
            "`OpenTelemetrySpanExt::set_attribute` stopped reaching the bridge \
             through `Filtered` — every redacted span sink is now a silent \
             no-op, which is worse than the leak this filter closes. \
             Attributes: {attrs}"
        );
        assert!(
            events.iter().any(|e| e == "deliberate-span-event"),
            "`OpenTelemetrySpanExt::add_event` stopped reaching the bridge \
             through `Filtered`: {events:?}"
        );
        assert!(
            status.contains("deliberate-span-status"),
            "`OpenTelemetrySpanExt::set_status` stopped reaching the bridge \
             through `Filtered`: {status}"
        );

        // Arm 3 — the invariant this change exists for.
        assert!(
            !events.iter().any(|e| e.contains("AKIA")),
            "a `tracing` event was promoted to a span event by the shared bridge \
             layer. The event-drop filter in \
             `talos_trace::otel_bridge_layer_with_tracer` has changed or been \
             bypassed — re-read the tracing-enablement analysis before accepting \
             this: {events:?}"
        );
    }
}
