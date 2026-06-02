//! W3C TraceContext propagation over NATS message headers.
//!
//! Two halves of the same coin:
//! * [`inject_trace_context`] — controller side, before `publish`.
//! * [`extract_trace_context`] — worker side, on receipt.
//!
//! Both are tied to the global [`opentelemetry::global::get_text_map_propagator`],
//! so installing a different propagator (Jaeger B3, etc.) at startup is the
//! only knob; this crate doesn't pick a wire format.

use opentelemetry::propagation::{Extractor, Injector};
use std::str::FromStr;
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub struct NatsHeaderInjector<'a> {
    headers: &'a mut async_nats::HeaderMap,
}

impl<'a> NatsHeaderInjector<'a> {
    pub fn new(headers: &'a mut async_nats::HeaderMap) -> Self {
        Self { headers }
    }
}

impl<'a> Injector for NatsHeaderInjector<'a> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(name) = async_nats::HeaderName::from_str(key) {
            if let Ok(val) = async_nats::HeaderValue::from_str(value.as_str()) {
                self.headers.insert(name, val);
            }
        }
    }
}

pub fn inject_trace_context(headers: &mut async_nats::HeaderMap) {
    let context = tracing::Span::current().context();
    opentelemetry::global::get_text_map_propagator(|propagator| {
        let mut injector = NatsHeaderInjector::new(headers);
        propagator.inject_context(&context, &mut injector);
    });
}

pub struct NatsHeaderExtractor<'a> {
    headers: &'a async_nats::HeaderMap,
}

impl<'a> NatsHeaderExtractor<'a> {
    pub fn new(headers: &'a async_nats::HeaderMap) -> Self {
        Self { headers }
    }
}

impl<'a> Extractor for NatsHeaderExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        if let Ok(name) = async_nats::HeaderName::from_str(key) {
            self.headers.get(name).map(|v| v.as_str())
        } else {
            None
        }
    }

    fn keys(&self) -> Vec<&str> {
        self.headers.iter().map(|(k, _)| k.as_ref()).collect()
    }
}

pub fn extract_trace_context(headers: &async_nats::HeaderMap) -> opentelemetry::Context {
    let extractor = NatsHeaderExtractor::new(headers);
    opentelemetry::global::get_text_map_propagator(|propagator| propagator.extract(&extractor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::propagation::TextMapPropagator;
    use opentelemetry::trace::{
        SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState,
    };
    use opentelemetry::Context;
    use opentelemetry_sdk::propagation::TraceContextPropagator;

    fn known_remote_context(trace_id: TraceId) -> Context {
        let sc = SpanContext::new(
            trace_id,
            SpanId::from_hex("b7ad6b7169203331").unwrap(),
            TraceFlags::SAMPLED,
            true, // remote
            TraceState::default(),
        );
        Context::new().with_remote_span_context(sc)
    }

    /// The W3C `traceparent` must survive an inject → NATS-header → extract
    /// round-trip once the propagator is installed. This is what
    /// `talos_trace::init_tracing` wires up globally; without the propagator the
    /// global default is a no-op and the header is never written, which silently
    /// breaks controller→worker trace continuity.
    #[test]
    fn traceparent_round_trips_over_nats_headers() {
        let propagator = TraceContextPropagator::new();
        let trace_id = TraceId::from_hex("0af7651916cd43dd8448eb211c80319c").unwrap();

        // Inject a known context into NATS headers via our Injector.
        let mut headers = async_nats::HeaderMap::new();
        propagator.inject_context(
            &known_remote_context(trace_id),
            &mut NatsHeaderInjector::new(&mut headers),
        );
        assert!(
            headers.get("traceparent").is_some(),
            "traceparent header must be injected into the NATS HeaderMap"
        );

        // Extract it back via our Extractor and confirm the trace_id survived.
        let extracted = propagator.extract(&NatsHeaderExtractor::new(&headers));
        assert_eq!(
            extracted.span().span_context().trace_id(),
            trace_id,
            "extracted trace_id must match the injected one"
        );
    }

    /// `extract_trace_context` (the worker-side consume path) must read the
    /// traceparent when the global propagator is installed — pinning the
    /// behaviour the worker relies on to link job spans to the controller trace.
    #[test]
    fn extract_trace_context_reads_traceparent_with_global_propagator() {
        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

        let trace_id = TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap();
        let mut headers = async_nats::HeaderMap::new();
        TraceContextPropagator::new().inject_context(
            &known_remote_context(trace_id),
            &mut NatsHeaderInjector::new(&mut headers),
        );

        let cx = extract_trace_context(&headers);
        assert_eq!(
            cx.span().span_context().trace_id(),
            trace_id,
            "extract_trace_context must recover the propagated trace_id"
        );
    }
}
