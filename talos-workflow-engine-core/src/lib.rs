//! Core data model + trait boundaries for a portable workflow
//! execution engine.
//!
//! This crate is **types + traits only**. It deliberately carries no
//! async runtime, no I/O, and no expression-evaluator dependency. An
//! executor crate layers the scheduling loop on top of these types
//! and plugs in consumer-supplied impls for each trait boundary.
//!
//! # What the executor does with these types
//!
//! The executor (see the sibling `talos-workflow-engine` crate for the
//! reference DAG scheduler + dispatch loop) owns the scheduling
//! loop. Given a graph of [`SystemNodeKind`]-typed nodes connected
//! by [`EdgeLogic`], it:
//!
//! * **Topologically orders** the graph and detects linear chains.
//!   Maximal sequences of nodes with in-degree = out-degree = 1 are
//!   batched through [`NodeDispatcher::dispatch_chain`] as a single
//!   pipeline dispatch — one transport round-trip and one shared
//!   sandbox for the whole chain instead of per-node overhead.
//! * **Fans out** non-chain nodes via [`NodeDispatcher::dispatch`] on
//!   `tokio::spawn` with a configurable concurrency cap, and joins
//!   siblings via [`JoinMode`] (All / Any / Majority / N).
//! * **Speculatively prefetches** module artifacts for a node's
//!   downstream successors (via the [`ModuleFetcher`] trait) while
//!   the parent still runs — hiding fetch latency behind execution.
//! * **Supports sub-workflow primitives**: every one of
//!   [`SystemNodeKind`]'s variants (`SubWorkflow`, `Judge`,
//!   `Ensemble`, `AgentLoop`, `ReActLoop`, `ReflectiveRetry`,
//!   `LlmDispatch`, `DynamicDispatch`, `CapabilityDispatch`,
//!   `ConfidenceGate`, `Verify`, `Synthesize`, `Collect`,
//!   `FanIn`, `WhileLoop`, `RepeatLoop`, `Wait`, `ErrorHandler`) is
//!   dispatched through a matching handler that composes
//!   [`NodeDispatcher`] with engine-local state. Sub-workflow graphs
//!   are batch-prefetched at run start (one `WHERE id = ANY($1)`
//!   query via [`WorkflowGraphStore`]) to eliminate N+1 lookups.
//! * **Persists and resumes paused runs** via [`CheckpointStore`] —
//!   `Wait` / cancelled runs snapshot per-node outputs through
//!   [`CheckpointStore::save`]; a subsequent resume hydrates them
//!   through [`CheckpointStore::load`].
//! * **Enforces security invariants** at every dispatch:
//!   [`SecretsResolver`] resolves per-node secrets; the executor
//!   refreshes short-lived credentials via
//!   [`SecretsResolver::refresh_vault_paths`] before handing them
//!   opaque-encrypted to the dispatcher; signed HMAC wire formats and
//!   topic-scoped queues are the dispatcher's concern.
//! * **Observes lifecycle events** via [`NodeLifecycleHook`] for
//!   per-node post-completion side effects (cost attribution, audit
//!   hooks, custom persistence).
//!
//! # Trait boundaries
//!
//! Every external-I/O concern the executor needs is behind exactly
//! one trait:
//!
//! * [`SecretsResolver`] — resolve module / vault / LLM-provider
//!   secrets; optional OAuth-style refresh hook.
//! * [`CheckpointStore`] — load a paused run's per-node outputs.
//! * [`WorkflowGraphStore`] — resolve sub-workflow graphs by id.
//! * [`NodeLifecycleHook`] — observe node completion for cross-cutting
//!   concerns.
//! * [`JobTransport`] — raw "send bytes, get bytes" channel to the
//!   worker pool (caller-owned timeout).
//! * [`NodeDispatcher`] — high-level "run this node (or chain of
//!   nodes)" primitive. Owns wire-format construction, signing,
//!   retry, and result parsing.
//!
//! Every trait the executor talks to for external I/O lives in this
//! crate. A production controller typically ships adapters that wire
//! real infrastructure behind each trait (for example: Postgres for
//! graph + events + checkpoint storage, a signed-NATS job protocol
//! for dispatch, and `rhai` + DLP scrubbing + retry classification
//! for the policy hooks).
//!
//! # What's in this crate, what's not
//!
//! This crate is **types + trait boundaries** — it is the API the
//! executor commits to, nothing more. See the crate README for
//! non-goals. The executor implementation itself lives in the
//! downstream crate that uses these traits.

#![cfg_attr(docsrs, feature(doc_cfg))]
// Every public item in this crate is part of the trait surface that
// the rest of the family depends on. `deny(missing_docs)` makes any
// undocumented `pub` item a compile error, preventing future
// regressions on the API contract. The crate is already fully
// documented as of 2026-04 — the deny gates new additions, not
// existing code.
#![deny(missing_docs)]

/// Compile-time witness for the `llm-primitives` feature on this crate.
///
/// Sibling crates that depend on `talos-workflow-engine-core` and also
/// expose an `llm-primitives` feature use this constant to assert
/// feature-flag coherence at compile time:
///
/// ```ignore
/// // In talos-workflow-engine/src/lib.rs:
/// const _: () = assert!(
///     talos_workflow_engine_core::HAS_LLM_PRIMITIVES
///         == cfg!(feature = "llm-primitives"),
///     "feature mismatch — see docs",
/// );
/// ```
///
/// `true` when the feature is enabled on **this** crate, `false`
/// otherwise. Cargo unifies features across the dependency graph, so
/// the only mismatch this catches is the one a misconfigured
/// `Cargo.toml` can actually produce: enabling `llm-primitives` on
/// `talos-workflow-engine-core` while disabling it on the engine.
pub const HAS_LLM_PRIMITIVES: bool = cfg!(feature = "llm-primitives");

mod approval_gate;
mod assistant_report_reader;
mod checkpoint;
mod context;
mod dispatcher;
mod edge;
mod egress_scope;
mod event_sink;
mod expression;
mod graph_store;
mod judge_score_recorder;
mod llm_tier;
mod module_artifact;
mod module_execution_store;
mod module_fetcher;
mod node_hook;
mod ops_alerts_reader;
mod pending_approvals_reader;
mod rate_limit;
pub mod reserved_keys;
mod retry;
mod retry_classifier;
mod sanitizer;
mod secret_envelope;
mod secrets;
mod shared_key;
mod sub_actor_context;
mod system_node;
mod transport;
mod wasm_cache;
mod write_ceiling;

pub use approval_gate::{ApprovalGate, ApprovalStatus};
pub use assistant_report_reader::AssistantReportReader;
pub use checkpoint::CheckpointStore;
pub use context::WorkflowContext;
pub use dispatcher::{
    dispatch_chain_sequential, ChainDispatchRequest, ChainDispatchResult, ChainStepResult,
    DispatchJob, DispatchJobBuilder, DispatchResult, NodeDispatcher, StepStatus,
    DEFAULT_DISPATCH_TIMEOUT_SECS,
};
pub use edge::EdgeLogic;
pub use egress_scope::EgressScope;
pub use event_sink::{EventSink, NodeEventWrite};
pub use expression::ExpressionEvaluator;
pub use graph_store::WorkflowGraphStore;
pub use judge_score_recorder::JudgeScoreRecorder;
pub use llm_tier::LlmTier;
pub use module_artifact::WasmModuleArtifact;
pub use module_execution_store::{ExecutionStartedContext, ModuleExecutionStore};
pub use module_fetcher::ModuleFetcher;
pub use node_hook::{NodeCompletionContext, NodeLifecycleHook};
pub use ops_alerts_reader::OpsAlertsReader;
pub use pending_approvals_reader::PendingApprovalsReader;
pub use rate_limit::RateLimitStore;
pub use retry::RetryPolicy;
pub use retry_classifier::RetryClassifier;
pub use sanitizer::{ExecutionSanitizer, OutputSanitizer};
pub use secret_envelope::{
    validate_seal_output, SealValidationError, SecretEnvelope, MIN_SEAL_NONCE_LEN,
};
pub use secrets::{
    BoxError, GcpImpersonationTokenProvider, GithubInstallationTokenProvider, SecretsResolver,
};
pub use shared_key::{WorkerKeyRing, WorkerSharedKey};
pub use sub_actor_context::SubworkflowActorContextResolver;
pub use system_node::{JoinMode, SystemNodeKind};
pub use transport::JobTransport;
pub use wasm_cache::{scoped_wasm_cache_key, scoped_wasm_redis_uri};
pub use write_ceiling::WriteCeiling;
