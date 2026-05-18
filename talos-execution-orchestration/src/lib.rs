//! Workflow execution orchestration service.
//!
//! Owns the trigger / replay / replay-with-input / retry orchestration that
//! used to live inline across `talos-mcp-handlers/src/executions.rs` (replay,
//! replay-with-input, retry) and `talos-mcp-handlers/src/workflows.rs`
//! (trigger). All four share a common skeleton:
//!
//!   1. Validate caller args + load the workflow / target execution row.
//!   2. Authorize (capability ceiling, actor budget, ownership) — for
//!      trigger this routes through `talos_workflow_authorization`.
//!   3. Persist a new execution row (or reset the existing one for retry).
//!   4. Build a `talos_engine` instance via `builder::for_workflow` with
//!      registry + secrets-manager + actor-repo + (optional) actor context.
//!   5. Dispatch via `nats_run::run_with_trigger_input_via_nats`, captured
//!      in a spawned task that publishes failure alerts + webhooks on the
//!      error path.
//!
//! Cross-protocol: this crate is consumed by both the MCP handlers
//! (`talos-mcp-handlers`) and the GraphQL `triggerWorkflow` mutation
//! (`talos-api`), the same `Arc<ExecutionOrchestrationService>` injected
//! into both contexts. The service has no protocol-specific branching.
//!
//! Pure helpers (`deep_merge`, `count_memory_write_nodes`, validation
//! helpers) are in submodules and unit-tested without a database.

#![forbid(unsafe_code)]

mod count_memory_write_nodes;
mod deep_merge;
mod errors;
mod failure_webhook;
mod input;
mod outcome;
mod replay;
mod retry;
mod trigger;

pub use count_memory_write_nodes::count_memory_write_nodes;
pub use deep_merge::deep_merge;
pub use errors::OrchestrationError;
pub use input::{ReplayInput, ReplayWithInputInput, RetryInput, TriggerInput};
pub use outcome::{
    DryRunResult, ExecutionOutcome, ExecutionStatus, TriggerMetadata, TriggerOutcome, TriggerType,
};

use std::sync::Arc;

use talos_actor_repository::ActorRepository;
use talos_execution_repository::ExecutionRepository;
use talos_registry::ModuleRegistry;
use talos_secrets_manager::SecretsManager;
use talos_workflow_repository::WorkflowRepository;

// Re-export so consumers get the opaque key type without depending
// directly on the workflow-engine-core crate.
pub use talos_workflow_engine_core::WorkerSharedKey;

/// Workflow execution orchestration service.
///
/// Holds Arc-wrapped dependencies; safe to clone (cheap reference-count
/// bumps). Constructed once at controller boot and shared across the
/// MCP handler tree, the GraphQL schema, and any other protocol surface.
///
/// `nats_client` is `Option` so unit tests and dev environments without
/// a NATS bus can construct the service; dispatch methods fail closed
/// with `OrchestrationError::DispatchFailed` when it's `None`.
///
/// `worker_shared_key` is loaded from `WORKER_SHARED_KEY` (or
/// `WORKER_SHARED_KEY_FILE`) at construction; absence in production is
/// fail-closed at dispatch time, matching the engine's
/// `run_with_trigger_input_via_nats` pre-flight added in r293.
pub struct ExecutionOrchestrationService {
    pub(crate) workflow_repo: Arc<WorkflowRepository>,
    pub(crate) execution_repo: Arc<ExecutionRepository>,
    pub(crate) actor_repo: Arc<ActorRepository>,
    pub(crate) secrets_manager: Arc<SecretsManager>,
    pub(crate) registry: Arc<ModuleRegistry>,
    pub(crate) nats_client: Option<Arc<async_nats::Client>>,
    pub(crate) worker_shared_key: Option<WorkerSharedKey>,
    /// Pool used by `talos_workflow_authorization::authorize_workflow_trigger`
    /// and the audit-log path. The authorization helper is the single
    /// caller that needs raw pool access; everything else flows through
    /// the per-domain repositories.
    pub(crate) db_pool: sqlx::PgPool,
}

impl ExecutionOrchestrationService {
    /// Build with explicit dependencies. The controller's wiring layer
    /// is the single canonical caller; tests use `test_stub` instead.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workflow_repo: Arc<WorkflowRepository>,
        execution_repo: Arc<ExecutionRepository>,
        actor_repo: Arc<ActorRepository>,
        secrets_manager: Arc<SecretsManager>,
        registry: Arc<ModuleRegistry>,
        nats_client: Option<Arc<async_nats::Client>>,
        worker_shared_key: Option<WorkerSharedKey>,
        db_pool: sqlx::PgPool,
    ) -> Self {
        Self {
            workflow_repo,
            execution_repo,
            actor_repo,
            secrets_manager,
            registry,
            nats_client,
            worker_shared_key,
            db_pool,
        }
    }

    // ---- Method stubs filled in by subsequent commits ---------------

    // pub async fn trigger(&self, input: TriggerInput) -> Result<ExecutionOutcome, OrchestrationError>
    // pub async fn replay(&self, input: ReplayInput) -> Result<ExecutionOutcome, OrchestrationError>
    // pub async fn replay_with_input(&self, input: ReplayWithInputInput) -> Result<ExecutionOutcome, OrchestrationError>
    // pub async fn retry(&self, input: RetryInput) -> Result<ExecutionOutcome, OrchestrationError>
}
