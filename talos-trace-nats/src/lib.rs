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
