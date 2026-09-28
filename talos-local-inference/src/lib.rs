//! Local (Ollama) inference, shared by every process that calls it — RFC 0014.
//!
//! * [`gate`]: the per-process in-flight gate (cap 1 by default). It queues and
//!   never refuses.
//! * [`stream`]: one exchange, streamed and bounded by progress deadlines
//!   ([`deadlines`]) instead of a total clock, reassembled into the
//!   non-streaming response body.
//! * [`line_reader`]: the byte-level line reader the stream is built on.
//!
//! Two callers: the worker's `llm::complete*` host functions (since P1/P2) and
//! the controller's `talos_llm::OllamaClient` (since P3a). They are different
//! processes, so each has its own gate; a queue shared across processes is P3b.

pub mod deadlines;
pub mod gate;
pub mod line_reader;
pub mod stream;
