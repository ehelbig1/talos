//! The deadlines of one LOCAL (Ollama) exchange — RFC 0014 P1.
//!
//! One home for both processes that talk to the local backend: the worker's
//! `llm::complete*` host functions and the controller's
//! `talos_llm::OllamaClient` (RFC 0014 P3a).

/// RFC 0014 P1: a local (Ollama) exchange is STREAMED and cut when it stops
/// making progress, not when a total clock runs out. Until 2026-09-28 it had
/// one 60 s total deadline over load + prompt evaluation + generation, which
/// cannot tell a slow answer from a stuck one: measured over 32 days, 47
/// requests were cut at exactly 60 s, and on 2026-09-28 the flagship
/// briefing's first attempt was cut while it was the only request on a
/// loaded model. See [`crate::stream`].
///
/// Until any byte of the answer arrives: send, model load, prompt evaluation.
pub const LOCAL_LLM_FIRST_BYTE_TIMEOUT_SECS: u64 = 60;
/// Between any two chunks of the answer.
pub const LOCAL_LLM_IDLE_TIMEOUT_SECS: u64 = 60;
/// The whole exchange — a backstop, not the working bound. The node's attempt
/// window (120 s by default) is expected to end a long call first.
pub const LOCAL_LLM_EXCHANGE_CEILING_SECS: u64 = 600;
/// The Pareto property of RFC 0014 P1, pinned at compile time: a call that
/// finished inside the old 60 s total deadline received its first byte within
/// 60 s and never waited more than 60 s between chunks, so it passes the new
/// rule. Lowering either deadline below the old total would break that
/// guarantee — Ollama sends nothing while it buffers a tool call's text — and
/// must be argued from measurement, not tuned here.
const PRE_RFC_0014_LOCAL_TOTAL_SECS: u64 = 60;
const _: () = assert!(
    LOCAL_LLM_FIRST_BYTE_TIMEOUT_SECS >= PRE_RFC_0014_LOCAL_TOTAL_SECS
        && LOCAL_LLM_IDLE_TIMEOUT_SECS >= PRE_RFC_0014_LOCAL_TOTAL_SECS
        && LOCAL_LLM_EXCHANGE_CEILING_SECS >= PRE_RFC_0014_LOCAL_TOTAL_SECS
);
