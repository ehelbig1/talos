use opentelemetry::propagation::Injector;
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
