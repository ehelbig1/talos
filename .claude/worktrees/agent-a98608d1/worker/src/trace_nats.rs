use opentelemetry::propagation::Extractor;
use std::str::FromStr;

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
