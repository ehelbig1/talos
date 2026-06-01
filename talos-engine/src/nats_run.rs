//! Controller-side wrappers around `talos-workflow-engine-nats`.
//!
//! Adds Talos-specific fallback wiring for the dispatcher's policy
//! adapters ([`RhaiEvaluator`] and [`HeuristicRetryClassifier`]) so
//! bare test engines still run without explicit setup, and provides
//! one-call entry points over a raw `async_nats::Client`.
//!
//! External consumers of `talos-workflow-engine-nats` typically skip this
//! module entirely: they build their own dispatcher and call
//! `talos_workflow_engine_nats::run_with_nats(...)` directly. These
//! wrappers exist purely as Talos convenience.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value as JsonValue;
use talos_workflow_engine::{ParallelWorkflowEngine, WorkflowEngineError};
use talos_workflow_engine_core::{NodeDispatcher, WorkerSharedKey, WorkflowContext};
use talos_workflow_engine_nats::{NatsNodeDispatcher, NatsTransport};
use uuid::Uuid;

use crate::expression_evaluator::RhaiEvaluator;
use crate::retry_classifier::HeuristicRetryClassifier;

/// Production gate: refuse to dispatch over NATS when the worker shared
/// key (HMAC root for JobRequest / PipelineJobRequest signing) is not
/// configured. Without it, jobs are unsigned and an on-wire attacker can
/// forge or replay them. Dev/test keep best-effort behaviour so local
/// workflows run without a configured `WORKER_SHARED_KEY`.
///
/// L-28: extracted from `run_with_trigger_input_via_nats` and applied
/// to ALL public NATS-dispatch entry points. Previously the seed
/// variant (used by workflow chains and resume-from-checkpoint) had no
/// guard — a misconfigured production controller would silently
/// dispatch unsigned jobs after a restart.
fn ensure_signing_key_present_in_production(
    worker_shared_key: Option<&WorkerSharedKey>,
    execution_id: Uuid,
) -> Result<(), WorkflowEngineError> {
    // MCP-671 (2026-05-13): route through `talos_config::is_production()`
    // so `RUST_ENV=""` (helm placeholder) doesn't silently bypass the
    // unsigned-dispatch refusal. Pre-fix: `Ok("")` != `Ok("production")`
    // produced false → unsigned dispatch allowed even when operator
    // sets `RUST_ENV=production` upstream but the value gets blanked
    // somewhere in the rendering chain. Sibling fail-open to the
    // worker NATS-auth gate closed in MCP-668.
    if worker_shared_key.is_none() && talos_config::is_production() {
        tracing::error!(
            execution_id = %execution_id,
            "SECURITY: refusing NATS dispatch with no WORKER_SHARED_KEY in production. \
             Job signing is required to prevent on-wire forgery and replay."
        );
        return Err(WorkflowEngineError::Execution(
            "WORKER_SHARED_KEY missing in production — refusing unsigned dispatch".to_string(),
        ));
    }
    Ok(())
}

/// Build the Talos default `NodeDispatcher` from a raw
/// `async_nats::Client`. Used by `run_with_nats`, `run_with_seed_via_nats`,
/// and `run_with_trigger_input_via_nats` so construction is in exactly
/// one place. Also used by direct callers of `execute_subworkflow_graph`
/// (e.g. `subworkflow_contract_service`).
pub fn build_nats_dispatcher(
    engine: &ParallelWorkflowEngine,
    nats_client: Arc<async_nats::Client>,
    worker_shared_key: Option<WorkerSharedKey>,
) -> Arc<dyn NodeDispatcher> {
    let transport = NatsTransport::shared(nats_client);
    // Fall back to the default Talos adapters when the engine was
    // constructed without explicit policy wiring (bare test engines).
    // Production paths (builders in `engine::builder`) always populate
    // these, so this fallback never fires on real traffic.
    let retry_classifier = engine
        .retry_classifier_arc()
        .unwrap_or_else(|| Arc::new(HeuristicRetryClassifier::new()));
    let expression_evaluator = engine
        .expression_evaluator_arc()
        .unwrap_or_else(|| Arc::new(RhaiEvaluator::new()));
    let event_sink = engine.event_sink_arc();
    Arc::new(NatsNodeDispatcher::new(
        transport,
        event_sink,
        worker_shared_key,
        retry_classifier,
        expression_evaluator,
    ))
}

/// Controller-convenience: dispatch via a raw `async_nats::Client`.
/// Wraps the client in `NatsTransport`, builds a `NatsNodeDispatcher`
/// with Talos fallback policy adapters, and delegates to the engine's
/// `run_with_transport`.
pub async fn run_with_nats(
    engine: &ParallelWorkflowEngine,
    nats_client: Arc<async_nats::Client>,
    worker_shared_key: Option<WorkerSharedKey>,
    execution_id: Uuid,
) -> Result<WorkflowContext, WorkflowEngineError> {
    ensure_signing_key_present_in_production(worker_shared_key.as_ref(), execution_id)?;
    let dispatcher = build_nats_dispatcher(engine, nats_client, worker_shared_key.clone());
    talos_workflow_engine_nats::run_with_nats(engine, dispatcher, worker_shared_key, execution_id)
        .await
}

/// Controller-convenience: seed + dispatch via a raw
/// `async_nats::Client`. See `run_with_nats` for the shim rationale.
///
/// # ⚠️ Do NOT call this with an empty `initial_results` for a fresh execution
///
/// This function does **not** install the synthetic `__trigger__` node
/// the engine wires onto root nodes during a normal trigger-input
/// dispatch. Calling it with `HashMap::new()` is correct **only** when
/// the workflow's roots do not reference `{{__trigger_input__.X}}` —
/// which in practice is true of almost no workflow in the platform.
/// For a fresh execution use
/// [`run_with_trigger_input_via_nats`] (with `serde_json::json!({})`
/// at minimum) so root-node template substitution sees an object,
/// not `null`. Reserve the seed path for **resume from a prior
/// checkpoint**, where `initial_results` already encodes the prior
/// trigger materialisation and a second synthetic trigger would
/// double-seed the roots.
///
/// History: violating this contract caused the r245 daily-brief 50%
/// failure-rate incident (scheduler was calling this with
/// `HashMap::new()`). `controller::scheduler::SchedulerDispatch`
/// codifies the correct selection.
pub fn run_with_seed_via_nats(
    engine: &ParallelWorkflowEngine,
    nats_client: Arc<async_nats::Client>,
    worker_shared_key: Option<WorkerSharedKey>,
    initial_results: HashMap<Uuid, JsonValue>,
    execution_id: Uuid,
) -> Pin<Box<dyn Future<Output = Result<WorkflowContext, WorkflowEngineError>> + Send + '_>> {
    // L-28: gate has to live INSIDE the returned Future since the function
    // signature returns a boxed future, not a `Result`. Build a future that
    // checks the gate first and short-circuits on failure.
    if let Err(e) =
        ensure_signing_key_present_in_production(worker_shared_key.as_ref(), execution_id)
    {
        return Box::pin(async move { Err(e) });
    }
    let dispatcher = build_nats_dispatcher(engine, nats_client, worker_shared_key.clone());
    talos_workflow_engine_nats::run_with_seed_via_nats(
        engine,
        dispatcher,
        worker_shared_key,
        initial_results,
        execution_id,
    )
}

/// Controller-convenience: dispatch a graph feeding `trigger_input` to
/// its roots via a raw `async_nats::Client`. Delegates to the engine's
/// [`ParallelWorkflowEngine::run_with_trigger_input_transport`], which
/// encapsulates the synthetic-trigger mechanism internally — callers
/// never touch engine graph internals.
///
/// SECURITY: the worker shared key is the HMAC root that signs every
/// `JobRequest` / `PipelineJobRequest`. Missing-key dispatch produces
/// unsigned jobs that an on-wire attacker can forge or replay. In
/// production we refuse to dispatch in that state — better to fail the
/// execution than to silently weaken the trust boundary. Dev/test
/// keep the previous best-effort behavior so local workflows run
/// without a configured WORKER_SHARED_KEY.
pub async fn run_with_trigger_input_via_nats(
    engine: &mut ParallelWorkflowEngine,
    nats_client: Arc<async_nats::Client>,
    worker_shared_key: Option<WorkerSharedKey>,
    trigger_input: JsonValue,
    execution_id: Uuid,
) -> Result<WorkflowContext, WorkflowEngineError> {
    ensure_signing_key_present_in_production(worker_shared_key.as_ref(), execution_id)?;
    let dispatcher = build_nats_dispatcher(engine, nats_client, worker_shared_key.clone());
    engine
        .run_with_trigger_input_transport(
            dispatcher,
            worker_shared_key,
            trigger_input,
            execution_id,
        )
        .await
}
