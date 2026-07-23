//! Memory-grounding evaluation for Talos actors.
//!
//! Answers "does memory grounding actually make an actor's responses better?"
//! two ways:
//!
//! - **Controlled A/B** ([`EvaluationService::run_ab_eval`]) — the causal
//!   experiment. Runs each eval task twice (memory grounding ON vs OFF via the
//!   existing `inject_memory_context` toggle), judges each output with a
//!   tier-gated LLM, and aggregates the paired deltas ([`stats`]).
//! - **Observational** ([`EvaluationService::observational_report`]) — the
//!   cheap correlational signal from already-accrued provenance.
//!
//! Security: the judge is itself an LLM call over the actor's response content
//! (which, for the ON arm, carries memory-derived personal data), so it reuses
//! the SAME fail-closed tier gate as the rest of the platform — a tier-1
//! actor's outputs are judged on LOCAL Ollama only, never an external provider.

pub mod error;
pub mod service;
pub mod stats;

pub use error::EvaluationError;
pub use service::{
    ArmResult, EvalRunInput, EvalRunOutcome, EvalTask, EvalTaskResult, EvaluationService,
    SkippedTask,
};
pub use stats::{
    aggregate_paired, analyze_observational, EvalSummary, LiftVerdict, ObservationalReport,
    ObservationalRow, PairedResult,
};
