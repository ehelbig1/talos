//! Progress-based deadlines for a LOCAL (Ollama) LLM exchange — RFC 0014 P1.
//!
//! The exchange lives in `talos_local_inference::stream` since RFC 0014 P3a,
//! shared with the controller's `OllamaClient`. The tests here drive it
//! against this worker's provider adapter.

pub(crate) use talos_local_inference::stream::{
    exchange_local_stream, request_streaming, LocalExchangeError, ProgressDeadlines,
};
#[cfg(test)]
pub(crate) use talos_local_inference::stream::{OllamaStreamAssembler, StallKind};

#[cfg(test)]
#[path = "llm_local_stream_tests.rs"]
mod tests;
