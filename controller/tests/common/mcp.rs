//! One home for the real `McpState` an MCP DB-test drives.
//!
//! Three binaries needed this constructor before it lived anywhere
//! (`swallowed_read_disclosure_tests`, `fail_open_gate_tests`, and the two
//! added on 2026-09-08), and a hand-copied 130-line struct literal is a
//! drift surface: a field added to `McpState` must be added in every copy, and
//! a copy that falls behind fails to COMPILE rather than silently — but a copy
//! that constructs a DIFFERENT service (a stub registry, a null repo) fails
//! silently and makes its binary's assertions prove nothing about production.
//! Included with `#[path = "common/mcp.rs"] mod mcp_common;` only by the
//! binaries that need it, so it costs the other test targets nothing.

#![allow(dead_code)]

use std::sync::Arc;
use uuid::Uuid;

use controller::mcp::auth::AgentIdentity;
use controller::mcp::McpState;

/// Build a real `McpState` over an isolated pool.
///
/// Every field is the production constructor — the point of these tests is that
/// the HANDLER BODY classifies, and a hand-rolled stand-in for the state would
/// prove nothing about it. NATS / LLM / Ollama are `None`, which is the shape
/// every dispatch-free read path already runs under.
pub async fn mcp_state(db_pool: sqlx::PgPool) -> McpState {
    let registry = Arc::new(controller::registry::ModuleRegistry::new(
        db_pool.clone(),
        None,
    ));
    let runtime = Arc::new(
        talos_worker_runtime::runtime::TalosRuntime::with_resources(None, None, None)
            .expect("runtime"),
    );
    let (compilation_event_tx, _rx) =
        tokio::sync::broadcast::channel::<controller::engine::events::CompilationEvent>(8);
    let compiler = Arc::new(controller::compilation::CompilationService::new(
        std::path::PathBuf::from("/tmp/talos-compilations-test"),
        compilation_event_tx,
    ));
    let circuit_breaker = Arc::new(controller::webhooks::CircuitBreaker::new());
    let dlp_service = Arc::new(controller::dlp::DlpService::from_env());
    let workflow_repo = Arc::new(talos_workflow_repository::WorkflowRepository::new(
        db_pool.clone(),
    ));
    let execution_repo = Arc::new(talos_execution_repository::ExecutionRepository::new(
        db_pool.clone(),
    ));
    let analytics_repo = Arc::new(talos_analytics_repository::AnalyticsRepository::new(
        db_pool.clone(),
    ));
    let advanced_repo = Arc::new(talos_advanced_repository::AdvancedRepository::new(
        db_pool.clone(),
    ));
    let actor_repo = Arc::new(talos_actor_repository::ActorRepository::new(
        db_pool.clone(),
    ));
    let module_repo = Arc::new(talos_module_repository::ModuleRepository::new(
        db_pool.clone(),
    ));
    let secrets_manager =
        Arc::new(controller::secrets::SecretsManager::new(db_pool.clone()).expect("secrets"));

    let policy_evaluator = talos_actor_policies::PolicyEvaluator::new(
        db_pool.clone(),
        actor_repo.clone(),
        advanced_repo.clone(),
    );

    McpState {
        db_pool: db_pool.clone(),
        registry: registry.clone(),
        agent_channels: Arc::new(dashmap::DashMap::new()),
        runtime: runtime.clone(),
        compiler: compiler.clone(),
        nats_client: None,
        llm_client: None,
        circuit_breaker,
        dlp_service: dlp_service.clone(),
        workflow_repo: workflow_repo.clone(),
        execution_repo: execution_repo.clone(),
        analytics_repo,
        advanced_repo: advanced_repo.clone(),
        actor_repo: actor_repo.clone(),
        module_repo: module_repo.clone(),
        secrets_manager: secrets_manager.clone(),
        ollama_client: None,
        policy_evaluator,
        workflow_creation_service: Arc::new(talos_workflow_creation::WorkflowCreationService::new(
            workflow_repo.clone(),
            None,
            dlp_service.clone(),
            module_repo.clone(),
            compiler.clone(),
        )),
        hot_update_service: Arc::new(talos_hot_update_service::HotUpdateService::new(
            module_repo.clone(),
            workflow_repo.clone(),
            compiler.clone(),
            db_pool.clone(),
        )),
        execution_orchestration_service: Arc::new(
            talos_execution_orchestration::ExecutionOrchestrationService::new(
                workflow_repo.clone(),
                execution_repo.clone(),
                actor_repo.clone(),
                secrets_manager.clone(),
                registry.clone(),
                None,
                None,
                db_pool.clone(),
            ),
        ),
        workflow_manifest_service: Arc::new(talos_workflow_manifest::WorkflowManifestService::new(
            workflow_repo.clone(),
            module_repo.clone(),
            secrets_manager.clone(),
        )),
        replay_service: Arc::new(talos_replay_service::ReplayService::new(
            registry.clone(),
            workflow_repo.clone(),
            module_repo.clone(),
            actor_repo.clone(),
            secrets_manager.clone(),
            runtime.clone(),
        )),
        inline_compile_service: Arc::new(talos_inline_compile_service::InlineCompileService::new(
            workflow_repo.clone(),
            module_repo.clone(),
            compiler.clone(),
            db_pool.clone(),
        )),
        search_service: Arc::new(talos_search_service::SearchService::new(
            workflow_repo.clone(),
        )),
        failure_analysis_service: Arc::new(
            talos_failure_analysis_service::FailureAnalysisService::new(execution_repo.clone()),
        ),
        actor_lifecycle_service: Arc::new(
            talos_actor_lifecycle_service::ActorLifecycleService::new(
                db_pool.clone(),
                registry.clone(),
                actor_repo.clone(),
                workflow_repo.clone(),
                module_repo.clone(),
                secrets_manager.clone(),
                None,
            ),
        ),
        hygiene_service: Arc::new(talos_hygiene_service::HygieneService::new(
            Arc::new(talos_analytics_repository::AnalyticsRepository::new(
                db_pool.clone(),
            )),
            workflow_repo.clone(),
            execution_repo.clone(),
            module_repo.clone(),
            // NOT CONSULTED — same statement as `push_channels` below.
            None,
        )),
        session_brief_service: Arc::new(talos_session_brief_service::SessionBriefService::new(
            advanced_repo.clone(),
        )),
        judge_probe_service: Arc::new(talos_judge_probe::JudgeProbeService::new(
            advanced_repo.clone(),
        )),
        // NOT CONSULTED — this harness wires no push-channel inventory, and the
        // tools it drives make no claim about push channels. The compiler asks
        // rather than defaulting, which is the point of the field being
        // `Option` (RFC 0012 P2's `from_scan` lesson).
        push_channels: None,
    }
}

pub fn agent(user_id: Uuid) -> Arc<AgentIdentity> {
    Arc::new(AgentIdentity {
        agent_id: Uuid::new_v4(),
        name: "package-23-probe".to_string(),
        role_name: "admin".to_string(),
        allowed_capabilities: vec!["*".to_string()],
        user_id: Some(user_id),
    })
}

/// The MCP text payload of a successful tool response, parsed as JSON.
pub fn text_json(resp: &controller::mcp::types::JsonRpcResponse) -> serde_json::Value {
    let text = resp
        .result
        .as_ref()
        .and_then(|r| r.pointer("/content/0/text"))
        .and_then(|t| t.as_str())
        .unwrap_or_else(|| panic!("expected a text result, got: {:?}", resp));
    serde_json::from_str(text).unwrap_or_else(|_| serde_json::Value::String(text.to_string()))
}

/// The refusal text of an MCP error response.
///
/// `mcp_error` renders a tool-level refusal INSIDE `result` (`isError: true`
/// plus the message as `content[0].text`) rather than in the JSON-RPC `error`
/// member, which is the MCP tool-error convention. Reading `resp.error` here
/// would make every assertion below pass or fail for the wrong reason.
pub fn error_message(resp: &controller::mcp::types::JsonRpcResponse) -> String {
    if let Some(e) = resp.error.as_ref() {
        return e.message.clone();
    }
    let r = resp
        .result
        .as_ref()
        .unwrap_or_else(|| panic!("expected a refusal, got: {:?}", resp));
    assert_eq!(
        r.get("isError").and_then(|v| v.as_bool()),
        Some(true),
        "expected a refusal, got: {r:?}"
    );
    r.pointer("/content/0/text")
        .and_then(|t| t.as_str())
        .unwrap_or_else(|| panic!("refusal carries no text: {r:?}"))
        .to_string()
}
