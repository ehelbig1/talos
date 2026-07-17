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
    // RFC 0010 P3 (D3b): keep a client handle for the claim responder before the
    // transport consumes `nats_client`.
    let nats_client_for_seal = nats_client.clone();
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
    let dispatcher = NatsNodeDispatcher::new(
        transport,
        event_sink,
        worker_shared_key.clone(),
        retry_classifier,
        expression_evaluator,
    );
    // Inject the result verify-ring: the current signing key plus any
    // WORKER_SHARED_KEY_PREVIOUS staged for a rolling rotation, so a worker
    // result signed under a previous key still verifies. Signing is unchanged
    // (always the current key). When no signing key is configured (test
    // harnesses) the dispatcher keeps its default `None` ring.
    let dispatcher = match worker_shared_key {
        Some(signing) => {
            let previous =
                talos_workflow_job_protocol::load_worker_shared_key_previous().unwrap_or_default();
            dispatcher.with_worker_key_ring(talos_workflow_engine_core::WorkerKeyRing::new(
                signing, previous,
            ))
        }
        None => dispatcher,
    };
    // RFC 0010 P1: when Ed25519 dispatch signing is configured, install the
    // signer so JobRequest/PipelineJobRequest are signed with the controller's
    // private key. Default (unconfigured) leaves it off → HMAC signing via
    // worker_shared_key, unchanged.
    let dispatcher = match resolve_dispatch_signer() {
        Some(signer) => {
            // RFC 0010 P3 (D3b): when TALOS_ENVELOPE_SEALING is on AND the
            // controller signs Ed25519 (required to sign SealedSecrets — P3
            // builds on P1), wire the shared claim responder + InFlightSeals
            // handle into the dispatcher. When sealing is on but no Ed25519
            // signing key is configured, we log and DON'T attach a handle —
            // the engine still resolved plaintext, so the dispatcher will
            // fail-closed per job (never leaking plaintext to the wire), making
            // the misconfiguration loud rather than silent.
            let dispatcher = dispatcher.with_dispatch_signer(signer.clone());
            if talos_envelope_seal::EnvelopeSealingMode::from_env().seals_claim_based() {
                if let talos_workflow_job_protocol::DispatchSigner::Ed25519(sk) = &signer {
                    let handle = envelope_sealing_handle(&nats_client_for_seal, sk.clone());
                    dispatcher.with_envelope_sealing(handle)
                } else {
                    tracing::error!(
                        target: "talos_security",
                        "TALOS_ENVELOPE_SEALING is on but no Ed25519 controller signing key is \
                         configured (TALOS_CONTROLLER_SIGNING_KEY) — claim-based sealing needs it \
                         to sign SealedSecrets. Claim dispatches will fail closed until it is set."
                    );
                    dispatcher
                }
            } else {
                dispatcher
            }
        }
        None => dispatcher,
    };
    Arc::new(dispatcher)
}

/// RFC 0010 P3 (D3b): the process-wide claim responder singleton + its
/// `InFlightSeals` + subject, created on first use. `build_nats_dispatcher` runs
/// per dispatch, but there must be exactly ONE responder + one shared store per
/// process — so it is memoized in a `OnceLock` and the responder task is spawned
/// once. Subsequent calls (and every dispatcher) reuse the same handle.
fn envelope_sealing_handle(
    nats_client: &Arc<async_nats::Client>,
    controller_key: Arc<talos_workflow_job_protocol::DispatchSigningKey>,
) -> talos_workflow_engine_nats::EnvelopeSealingHandle {
    static HANDLE: std::sync::OnceLock<talos_workflow_engine_nats::EnvelopeSealingHandle> =
        std::sync::OnceLock::new();
    HANDLE
        .get_or_init(|| {
            let in_flight = Arc::new(talos_envelope_seal::InFlightSeals::new());
            // Per-replica claim subject the dispatcher stamps into every
            // sealing=1 JobRequest.claim_inbox; the responder subscribes to it.
            // Because a NATS reply inbox is connection-scoped, the claim returns
            // to THIS replica (which holds the in-flight context).
            let claim_subject = nats_client.new_inbox();
            let nc = nats_client.clone();
            let subject = claim_subject.clone();
            let inf = in_flight.clone();
            tokio::spawn(async move {
                if let Err(e) = talos_envelope_seal::run_claim_responder(
                    nc,
                    subject,
                    inf,
                    controller_key,
                    // Freshness window for incoming claims (matches the worker's
                    // SealedSecrets window + the dispatch-verify window).
                    300,
                )
                .await
                {
                    tracing::error!(
                        target: "talos_security",
                        error = %e,
                        "RFC 0010 P3 claim responder exited"
                    );
                }
            });
            // RFC 0010 P3 (M4): bound `InFlightSeals` against ORPHANED seals.
            // The engine's request/reply dispatcher removes its context on
            // claim OR on the post-dispatch `discard`, but module-bound
            // fire-and-forget pushes (Gmail/GCal/webhooks) publish and return
            // immediately — they can't `discard`. A worker that dies before
            // claiming would strand its context here forever. A live worker
            // claims within milliseconds, so a generous TTL (default 10 min)
            // never races a legitimate claim. Spawned once, alongside the
            // responder, so it exists regardless of whether the engine or a
            // module-bound push initialised the handle first.
            let sweep_inf = in_flight.clone();
            // Floor the TTL at 60s: `positive_env_or_default` rejects 0/negative
            // but accepts e.g. `1`, and a TTL below any plausible dispatch→claim
            // latency (cold worker start, queue backlog) would evict LEGITIMATE
            // in-flight seals — fail-closed (job fails, no leak) but a needless
            // availability footgun. The doc contract "generously larger than
            // dispatch→claim latency" is enforced here, not by operator
            // discipline.
            let configured_ttl: u64 =
                talos_config::positive_env_or_default("TALOS_SEAL_ORPHAN_TTL_SECS", 600);
            let ttl_secs = configured_ttl.max(60);
            if ttl_secs != configured_ttl {
                tracing::warn!(
                    target: "talos_security",
                    configured_ttl,
                    "TALOS_SEAL_ORPHAN_TTL_SECS below the 60s floor; clamped to 60"
                );
            }
            let sweep_interval_secs: u64 =
                talos_config::positive_env_or_default("TALOS_SEAL_SWEEP_INTERVAL_SECS", 60);
            tokio::spawn(async move {
                let mut ticker =
                    tokio::time::interval(std::time::Duration::from_secs(sweep_interval_secs));
                // Skip the immediate first tick — nothing to sweep at startup.
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    let swept =
                        sweep_inf.sweep_older_than(std::time::Duration::from_secs(ttl_secs));
                    if swept > 0 {
                        tracing::warn!(
                            target: "talos_security",
                            swept,
                            ttl_secs,
                            "RFC 0010 P3 (M4): swept orphaned in-flight seals \
                             (worker never claimed within TTL)"
                        );
                    }
                }
            });
            tracing::info!(
                target: "talos_security",
                %claim_subject,
                "RFC 0010 P3 (D3b) claim responder started; claim-based secret sealing active"
            );
            talos_workflow_engine_nats::EnvelopeSealingHandle {
                in_flight,
                claim_subject,
            }
        })
        .clone()
}

/// RFC 0010 P3 (M4): expose the process-wide claim-sealing handle to the
/// module-bound (fire-and-forget) dispatch paths — Gmail / Google-Calendar
/// push, generic webhooks — which build `JobRequest`s directly instead of
/// going through the engine dispatcher.
///
/// Returns `Some` ONLY when claim-based sealing is active (`TALOS_ENVELOPE_
/// SEALING` ∈ {audit, required}) AND an Ed25519 controller signing key is
/// configured (P3 needs it to sign `SealedSecrets`) — the SAME gate
/// [`build_nats_dispatcher`] applies. Reuses the memoized `OnceLock`, so the
/// caller gets the SAME `InFlightSeals` + claim subject the claim responder
/// subscribes to (never construct a second store — the responder would never
/// see its registrations). Calling this at controller boot eagerly starts the
/// responder + sweep so they're ready before the first module-bound push.
///
/// Returns `None` when sealing is off, or when it's on but misconfigured (no
/// Ed25519 key). In the misconfigured case module-bound dispatch falls back to
/// the inline WSK envelope, which the worker refuses under `required` (loud,
/// fail-closed) — the same posture the engine takes.
pub fn shared_envelope_sealing_handle(
    nats_client: &Arc<async_nats::Client>,
) -> Option<talos_workflow_engine_nats::EnvelopeSealingHandle> {
    if !talos_envelope_seal::EnvelopeSealingMode::from_env().seals_claim_based() {
        return None;
    }
    match resolve_dispatch_signer() {
        Some(talos_workflow_job_protocol::DispatchSigner::Ed25519(sk)) => {
            Some(envelope_sealing_handle(nats_client, sk))
        }
        _ => {
            tracing::error!(
                target: "talos_security",
                "TALOS_ENVELOPE_SEALING is on but no Ed25519 controller signing key is \
                 configured — module-bound dispatch cannot claim-seal and will fall back to \
                 the inline envelope (refused under `required`). Set TALOS_CONTROLLER_SIGNING_KEY."
            );
            None
        }
    }
}

/// RFC 0010 P1: resolve the controller's dispatch signer. Delegates resolution
/// to [`talos_workflow_job_protocol::configured_dispatch_signer`] (the single
/// source of truth shared with the module-push + retry re-sign sites) and adds a
/// one-time boot diagnostic distinguishing "Ed25519 active" from
/// "requested-but-misconfigured → HMAC fallback".
fn resolve_dispatch_signer() -> Option<talos_workflow_job_protocol::DispatchSigner> {
    static LOGGED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    let signer = talos_workflow_job_protocol::configured_dispatch_signer();
    LOGGED.get_or_init(|| {
        let requested = std::env::var("TALOS_DISPATCH_SCHEME")
            .map(|s| s.eq_ignore_ascii_case("ed25519"))
            .unwrap_or(false);
        match (&signer, requested) {
            (Some(_), _) => tracing::info!(
                target: "talos_security",
                "dispatch signing scheme = Ed25519 (RFC 0010 P1)"
            ),
            (None, true) => tracing::error!(
                target: "talos_security",
                "TALOS_DISPATCH_SCHEME=ed25519 but TALOS_CONTROLLER_SIGNING_KEY is unset/invalid \
                 — falling back to HMAC dispatch signing"
            ),
            (None, false) => {}
        }
    });
    signer
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
