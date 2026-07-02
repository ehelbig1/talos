//! Actor lifecycle service: the scaffold (create-actor-with-everything)
//! and actor-to-actor handoff orchestration that previously lived inline
//! in `talos-mcp-handlers/src/actor.rs::handle_scaffold_actor` (~584 LoC
//! of nested arg validation feeding `talos_actor_scaffold`) and
//! `::handle_handoff_to_actor` (~570 LoC of status/chain/budget/
//! authorization gates + execution insert + engine dispatch).
//!
//! Architectural pattern: matches `talos-execution-orchestration` (r295),
//! `talos-workflow-manifest` (r302), `talos-replay-service` (r303), and
//! `talos-inline-compile-service` (r304). Arc-injected dependencies,
//! `thiserror` enums mapped to JSON-RPC codes via `jsonrpc_code()`, and
//! `user_facing_message()` accessors that keep internal detail (sqlx
//! errors, schema names, engine internals) server-side.
//!
//! Every operator-recognized string — the -32602 arg-shape rejections,
//! the -32000 status/budget/authorization rejections, and the handoff
//! response body — is copied verbatim from the pre-extraction handlers
//! and locked by the unit tests in `scaffold_args.rs` / `handoff.rs`.
//!
//! Both methods intentionally take the raw MCP `args` JSON: the
//! pre-extraction handlers interleaved argument parsing with DB-backed
//! checks (from-actor status BEFORE to-actor parse, etc.), so hoisting
//! all parsing into the protocol layer would reorder which error a
//! multiply-invalid request surfaces first. Keeping the whole sequence
//! in one place preserves first-failing-check semantics byte-for-byte.

#![forbid(unsafe_code)]

mod handoff;
mod scaffold_args;

pub use handoff::{HandoffError, HandoffOutcome};
pub use scaffold_args::parse_scaffold_request;

use std::sync::Arc;

use uuid::Uuid;

use talos_actor_repository::ActorRepository;
use talos_actor_scaffold::{scaffold_actor, ScaffoldError, ScaffoldOutcome, ScaffoldServiceDeps};
use talos_module_repository::ModuleRepository;
use talos_registry::ModuleRegistry;
use talos_secrets_manager::SecretsManager;
use talos_workflow_repository::WorkflowRepository;

// -----------------------------------------------------------------------------
// Scaffold errors
// -----------------------------------------------------------------------------

/// Failure modes from [`ActorLifecycleService::scaffold`]. Argument-shape
/// rejections carry the verbatim pre-extraction message; service-level
/// failures wrap [`talos_actor_scaffold::ScaffoldError`] and render
/// through its `user_message()` (which already collapses
/// `DatabaseError(_)` to the generic "Database error during scaffold").
#[derive(Debug)]
pub enum ScaffoldActorError {
    /// JSON-RPC `-32602`: bad argument shape. Message verbatim from the
    /// pre-extraction handler.
    InvalidArgs(String),
    /// Required-step failure from the scaffold service. Code mapping
    /// preserved from the pre-extraction handler match:
    /// `CapabilityCeilingExceeded` → `-32603`, `DatabaseError` →
    /// `-32000`, everything else → `-32602`.
    Service(ScaffoldError),
}

impl ScaffoldActorError {
    /// Stable JSON-RPC error code for protocol wrappers.
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::InvalidArgs(_) => -32602,
            Self::Service(ScaffoldError::CapabilityCeilingExceeded { .. }) => -32603,
            Self::Service(ScaffoldError::DatabaseError(_)) => -32000,
            Self::Service(_) => -32602,
        }
    }

    /// Caller-safe message for the protocol response. `Service` renders
    /// via `ScaffoldError::user_message()`, whose `DatabaseError` arm is
    /// a fixed generic string — sqlx detail never reaches the caller.
    pub fn user_facing_message(&self) -> String {
        match self {
            Self::InvalidArgs(m) => m.clone(),
            Self::Service(e) => e.user_message(),
        }
    }
}

// -----------------------------------------------------------------------------
// Service
// -----------------------------------------------------------------------------

/// Actor lifecycle orchestration. One shared instance backs the MCP
/// `scaffold_actor` and `handoff_to_actor` tools (plus the deprecated
/// `handoff_to_agent` alias) and is ready to back a future GraphQL
/// surface — same Arc, same gate sequence, same dispatch path.
pub struct ActorLifecycleService {
    db_pool: sqlx::PgPool,
    registry: Arc<ModuleRegistry>,
    actor_repo: Arc<ActorRepository>,
    workflow_repo: Arc<WorkflowRepository>,
    module_repo: Arc<ModuleRepository>,
    secrets_manager: Arc<SecretsManager>,
    nats_client: Option<Arc<async_nats::Client>>,
}

impl ActorLifecycleService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db_pool: sqlx::PgPool,
        registry: Arc<ModuleRegistry>,
        actor_repo: Arc<ActorRepository>,
        workflow_repo: Arc<WorkflowRepository>,
        module_repo: Arc<ModuleRepository>,
        secrets_manager: Arc<SecretsManager>,
        nats_client: Option<Arc<async_nats::Client>>,
    ) -> Self {
        Self {
            db_pool,
            registry,
            actor_repo,
            workflow_repo,
            module_repo,
            secrets_manager,
            nats_client,
        }
    }

    /// Scaffold an actor from raw MCP args: parse + validate the nested
    /// request shape (budget knobs, seed memories, starter workflow),
    /// then delegate to `talos_actor_scaffold::scaffold_actor` with this
    /// service's repositories.
    pub async fn scaffold(
        &self,
        user_id: Uuid,
        args: &serde_json::Value,
    ) -> Result<ScaffoldOutcome, ScaffoldActorError> {
        let request = parse_scaffold_request(args).map_err(ScaffoldActorError::InvalidArgs)?;
        let deps = ScaffoldServiceDeps {
            db_pool: self.db_pool.clone(),
            actor_repo: self.actor_repo.clone(),
            module_repo: self.module_repo.clone(),
            workflow_repo: self.workflow_repo.clone(),
        };
        scaffold_actor(&deps, user_id, request)
            .await
            .map_err(ScaffoldActorError::Service)
    }
}

// -----------------------------------------------------------------------------
// Shared pure helpers
// -----------------------------------------------------------------------------

/// JSON type name for arg-shape error messages. Verbatim copy of
/// `talos-mcp-handlers/src/utils.rs::json_type_name` — the handler crate
/// depends on this one, so the helper can't be imported from there.
pub(crate) fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_error_codes_stable() {
        assert_eq!(
            ScaffoldActorError::InvalidArgs("x".into()).jsonrpc_code(),
            -32602
        );
        assert_eq!(
            ScaffoldActorError::Service(ScaffoldError::CapabilityCeilingExceeded {
                user_ceiling: "http-node".into(),
                requested: "agent-node".into(),
            })
            .jsonrpc_code(),
            -32603
        );
        assert_eq!(
            ScaffoldActorError::Service(ScaffoldError::DatabaseError("boom".into())).jsonrpc_code(),
            -32000
        );
        assert_eq!(
            ScaffoldActorError::Service(ScaffoldError::InvalidName("bad".into())).jsonrpc_code(),
            -32602
        );
        assert_eq!(
            ScaffoldActorError::Service(ScaffoldError::DuplicateName("a".into())).jsonrpc_code(),
            -32602
        );
    }

    #[test]
    fn scaffold_database_error_never_leaks_detail() {
        // The DatabaseError inner string may carry sqlx/schema detail;
        // user_facing_message must collapse it to the generic string.
        let err = ScaffoldActorError::Service(ScaffoldError::DatabaseError(
            "INSERT INTO actors failed: relation actors_pkey violated".into(),
        ));
        let msg = err.user_facing_message();
        assert_eq!(msg, "Database error during scaffold");
        assert!(!msg.contains("INSERT"));
        assert!(!msg.contains("actors_pkey"));
    }

    #[test]
    fn json_type_name_covers_all_variants() {
        assert_eq!(json_type_name(&serde_json::json!(null)), "null");
        assert_eq!(json_type_name(&serde_json::json!(true)), "bool");
        assert_eq!(json_type_name(&serde_json::json!(1)), "number");
        assert_eq!(json_type_name(&serde_json::json!("s")), "string");
        assert_eq!(json_type_name(&serde_json::json!([])), "array");
        assert_eq!(json_type_name(&serde_json::json!({})), "object");
    }
}
