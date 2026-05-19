//! Test-only trait implementations for the workflow engine.
//!
//! This crate ships in-memory, capture-style, and no-op impls of every
//! trait defined in `talos-workflow-engine-core`. Consumers writing unit
//! tests for workflows — or embedding the engine in a test harness for
//! their own modules — pull these in as a `dev-dependency` and wire
//! them into a [`ParallelWorkflowEngine`] the same way they'd wire a
//! production adapter.
//!
//! [`ParallelWorkflowEngine`]: https://docs.rs/talos-workflow-engine
//!
//! # Organization
//!
//! Impls are grouped by what they're for:
//!
//! * [`capture`] — records every call so tests can assert on what the
//!   engine emitted ([`EventSink`], [`NodeLifecycleHook`],
//!   [`ModuleExecutionStore`]).
//! * [`memory`] — plain `HashMap`-backed stores for traits that need to
//!   return data ([`ModuleFetcher`], [`CheckpointStore`],
//!   [`WorkflowGraphStore`], [`SecretsResolver`]).
//! * [`noop`] — pass-through impls for policy traits a test doesn't
//!   care about ([`OutputSanitizer`], [`ExpressionEvaluator`],
//!   [`RetryClassifier`]).
//! * [`dispatch`] — scripted [`NodeDispatcher`] where the test declares
//!   `(module_id → response)` up front.
//! * [`approval`] — constant-outcome [`ApprovalGate`]s (always-approve,
//!   always-pending, always-deny).
//!
//! Every impl is `Send + Sync` and safe to share across spawned tasks.
//! Capture stores return owned clones of their internal state so test
//! assertions can't accidentally mutate the live log.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//! use uuid::Uuid;
//! use talos_workflow_engine_core::{DispatchJob, NodeDispatcher};
//! use talos_workflow_engine_test_utils::{
//!     capture::CaptureEventSink,
//!     dispatch::ScriptedDispatcher,
//!     memory::InMemoryModuleFetcher,
//! };
//!
//! # async fn demo() {
//! let fetcher = Arc::new(InMemoryModuleFetcher::new());
//! let events = Arc::new(CaptureEventSink::new());
//! let dispatcher = Arc::new(
//!     ScriptedDispatcher::new()
//!         .with_response(Uuid::nil(), serde_json::json!({ "ok": true })),
//! );
//! // Feed these into `ParallelWorkflowEngine::set_*` / your run fn,
//! // then assert on `events.events()` after the run.
//! # }
//! ```
//!
//! [`EventSink`]: talos_workflow_engine_core::EventSink
//! [`NodeLifecycleHook`]: talos_workflow_engine_core::NodeLifecycleHook
//! [`ModuleExecutionStore`]: talos_workflow_engine_core::ModuleExecutionStore
//! [`ModuleFetcher`]: talos_workflow_engine_core::ModuleFetcher
//! [`CheckpointStore`]: talos_workflow_engine_core::CheckpointStore
//! [`WorkflowGraphStore`]: talos_workflow_engine_core::WorkflowGraphStore
//! [`SecretsResolver`]: talos_workflow_engine_core::SecretsResolver
//! [`OutputSanitizer`]: talos_workflow_engine_core::OutputSanitizer
//! [`ExpressionEvaluator`]: talos_workflow_engine_core::ExpressionEvaluator
//! [`RetryClassifier`]: talos_workflow_engine_core::RetryClassifier
//! [`NodeDispatcher`]: talos_workflow_engine_core::NodeDispatcher
//! [`ApprovalGate`]: talos_workflow_engine_core::ApprovalGate

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod approval;
pub mod capture;
pub mod dispatch;
pub mod memory;
#[cfg(feature = "minimal")]
pub mod minimal;
pub mod noop;
pub mod rate_limit;

#[cfg(feature = "minimal")]
pub use minimal::minimal_engine;
