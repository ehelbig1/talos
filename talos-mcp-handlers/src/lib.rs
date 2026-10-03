use axum::{
    extract::State,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Json, Router,
};
use dashmap::DashMap;
use futures::stream::Stream;
use std::{convert::Infallible, time::Duration};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;

// ============================================================================
// SECURITY: Per-agent rate limiting (sliding window)
// ============================================================================

/// Tracks per-agent request counts within a sliding time window.
struct AgentRateLimiter {
    /// Maps agent_id -> (request_count, window_start)
    windows: DashMap<String, (u32, std::time::Instant)>,
    /// Maximum requests per window
    max_requests: u32,
    /// Window duration
    window_duration: Duration,
}

/// Defense-in-depth cap on `AgentRateLimiter::windows`.
///
/// MCP-1178 (2026-05-17): the prior `if .len() > 1_000 { retain }` was a
/// cleanup TRIGGER not a cap. Under burst where all entries are fresh
/// (within `window_duration * 2`), retain finds zero stale entries to
/// evict and the unconditional `entry().or_insert(...)` grows the map
/// past the trigger by 1 per call. Used by BOTH `AGENT_RATE_LIMITER`
/// (per-agent) and `USER_RATE_LIMITER` (per-user); bounded only by
/// distinct authenticated agent/user IDs which can reach 50K+ in a
/// large multi-tenant deployment. The O(N) retain scan ran on every
/// call past the trigger — at 100K entries that's 100K iterations per
/// request, real perf degradation under sustained burst.
///
/// 50_000 matches workspace canonical (MCP-1145 GRACE_CACHE_MAX_ENTRIES,
/// MCP-1146 MCP_AUTH_RATE_LIMITER_MAX_ENTRIES, MCP-1147
/// REFRESH_RATE_LIMITER_MAX_ENTRIES).
const AGENT_RATE_LIMITER_MAX_ENTRIES: usize = 50_000;

impl AgentRateLimiter {
    fn new(max_requests_per_min: u32) -> Self {
        Self {
            windows: DashMap::new(),
            max_requests: max_requests_per_min,
            window_duration: Duration::from_secs(60),
        }
    }

    /// Returns `true` if the request is allowed, `false` if rate-limited.
    fn check_and_increment(&self, agent_id: &str) -> bool {
        let now = std::time::Instant::now();

        // Periodic cleanup: remove expired entries when map grows large
        if self.windows.len() > 1_000 {
            self.windows.retain(|_, (_, window_start)| {
                now.duration_since(*window_start) < self.window_duration * 2
            });
        }

        // MCP-1178 (2026-05-17): fail-CLOSED at the defense-in-depth
        // cap. The retain above only evicts entries older than
        // `window_duration * 2` — under sustained burst where all
        // entries are fresh, retain is a no-op and the unconditional
        // `entry().or_insert(...)` below would grow the map past the
        // intended bound. Existing tracked keys continue through their
        // normal accounting (the `entry()` path touches existing keys,
        // not new ones); only NEW keys at-cap are refused, treated as
        // rate-limited so the attacker can't amplify burst into heap
        // exhaustion AND can't silently disable rate-limiting for
        // legitimate tracked keys. Same fail-CLOSED-at-cap posture as
        // MCP-1145 (CSRF grace cache), MCP-1146 (MCP auth rate
        // limiter), MCP-1147 (refresh rate limiter), MCP-1177
        // (BCRYPT_VERIFY_CACHE). `contains_key(agent_id)` is a cheap
        // O(1) DashMap lookup using the `Borrow<str>` impl on `String`.
        if self.windows.len() >= AGENT_RATE_LIMITER_MAX_ENTRIES
            && !self.windows.contains_key(agent_id)
        {
            tracing::warn!(
                target: "talos_audit",
                event_kind = "agent_rate_limiter_cap_hit",
                size = self.windows.len(),
                cap = AGENT_RATE_LIMITER_MAX_ENTRIES,
                "AgentRateLimiter at capacity after expired-eviction; refusing new key as rate-limited"
            );
            return false;
        }

        let mut entry = self.windows.entry(agent_id.to_string()).or_insert((0, now));

        let (count, window_start) = entry.value_mut();

        // If the window has expired, reset
        if now.duration_since(*window_start) >= self.window_duration {
            *count = 1;
            *window_start = now;
            return true;
        }

        // Within current window
        if *count >= self.max_requests {
            return false;
        }

        *count += 1;
        true
    }
}

static AGENT_RATE_LIMITER: std::sync::LazyLock<AgentRateLimiter> = std::sync::LazyLock::new(|| {
    // MCP-664: `MCP_AGENT_RATE_LIMIT_PER_MIN=0` would make every request
    // fail `*count >= self.max_requests` (0 >= 0 is true on first call),
    // taking the entire per-agent path offline. Sibling fix to the
    // auth-rate-limit envs above.
    let max_per_min: u32 =
        talos_config::positive_env_or_default("MCP_AGENT_RATE_LIMIT_PER_MIN", 1000u32);
    AgentRateLimiter::new(max_per_min)
});

/// Per-user rate limiter: caps total requests across ALL agents belonging to a single
/// user. Without this, a user could register N agents and obtain N × per-agent limit,
/// defeating the intent of the per-agent cap.
///
/// Default: 5000 req/min per user. Configurable via MCP_USER_RATE_LIMIT_PER_MIN.
/// Should be set to 3–5× the per-agent limit so a small number of legitimate agents
/// (e.g. two Claude Desktop instances) aren't accidentally throttled.
static USER_RATE_LIMITER: std::sync::LazyLock<AgentRateLimiter> = std::sync::LazyLock::new(|| {
    // MCP-664: sibling `=0` guard. Same shape as AGENT_RATE_LIMITER above.
    let max_per_min: u32 =
        talos_config::positive_env_or_default("MCP_USER_RATE_LIMIT_PER_MIN", 5000u32);
    AgentRateLimiter::new(max_per_min)
});

/// Process start time for uptime reporting in `get_platform_info`.
/// Exposed as `pub(crate)` so `main()` can force-initialize it at server
/// startup before any request handler runs, ensuring `elapsed()` reflects
/// true uptime rather than time since first `get_platform_info` call.
pub static PROCESS_START_TIME: std::sync::LazyLock<std::time::Instant> =
    std::sync::LazyLock::new(std::time::Instant::now);

use talos_compilation::CompilationService;
use talos_registry::ModuleRegistry;

pub mod actor;
pub mod advanced;
pub mod alerts;
pub mod analytics;
pub mod auth;
pub mod capability_worlds;
#[cfg(test)]
mod compile_refusal_pins;
pub mod configuration;
pub mod evaluation;
pub mod executions;
pub mod graph;
#[cfg(test)]
mod inherited_grants_pins;
#[cfg(test)]
mod install_grants_pin;
pub mod knowledge_graph;
pub mod ml;
pub mod modules;
pub mod ollama;
pub mod ops_alerts;
pub mod platform;
#[cfg(test)]
mod push_channel_wiring_tests;
pub mod resources;
#[cfg(test)]
mod restore_pinned_pin;
pub mod sandbox;
pub mod schedules;
pub mod schemas;
pub mod search;
#[cfg(test)]
mod secret_grant_delivery_pins;
pub mod secrets;
pub mod ssrf_resolver;
pub mod tool_hints;
pub mod tool_labels;
pub mod types;
pub mod utils;
pub mod versions;
pub mod webhooks;
pub mod workflows;

#[cfg(test)]
mod schema_parity_tests;
#[cfg(test)]
mod tests;

// ============================================================================
// Utility functions (re-exported from utils submodule)
// ============================================================================

use utils::mcp_error;

// -----------------------------------------------------------------------------
// MCP Types (re-exported from types submodule)
// -----------------------------------------------------------------------------

pub use types::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};

// -----------------------------------------------------------------------------
// App State for MCP
// -----------------------------------------------------------------------------

#[derive(Clone)]
pub struct McpState {
    pub db_pool: sqlx::PgPool,
    pub registry: std::sync::Arc<ModuleRegistry>,
    /// Per-agent SSE channels keyed by agent_id string.
    /// Each agent gets its own broadcast channel to prevent cross-agent data leakage.
    pub agent_channels: std::sync::Arc<DashMap<String, broadcast::Sender<Event>>>,
    pub runtime: std::sync::Arc<talos_worker_runtime::runtime::TalosRuntime>,
    pub compiler: std::sync::Arc<CompilationService>,
    /// Shared NATS client (authenticated, reused across all MCP requests).
    pub nats_client: Option<std::sync::Arc<async_nats::Client>>,
    /// Optional LLM client for AI-powered features (e.g., workflow scaffolding).
    /// Enabled when ANTHROPIC_API_KEY is set in the environment.
    pub llm_client: Option<std::sync::Arc<talos_llm::LlmClient>>,
    /// Webhook circuit breaker for per-IP auth failure tracking.
    pub circuit_breaker: std::sync::Arc<talos_webhooks::CircuitBreaker>,
    /// DLP service for PII redaction in handler call sites.
    pub dlp_service: std::sync::Arc<talos_dlp_provider::DlpService>,
    /// Centralised SQL repository for the workflows domain.
    pub workflow_repo: std::sync::Arc<talos_workflow_repository::WorkflowRepository>,
    /// Centralised SQL repository for the executions domain.
    pub execution_repo: std::sync::Arc<talos_execution_repository::ExecutionRepository>,
    /// Centralised SQL repository for the analytics domain.
    pub analytics_repo: std::sync::Arc<talos_analytics_repository::AnalyticsRepository>,
    /// Centralised SQL repository for the advanced-features domain.
    pub advanced_repo: std::sync::Arc<talos_advanced_repository::AdvancedRepository>,
    /// Centralised SQL repository for the actors domain.
    pub actor_repo: std::sync::Arc<talos_actor_repository::ActorRepository>,
    /// Centralised SQL repository for the modules domain.
    pub module_repo: std::sync::Arc<talos_module_repository::ModuleRepository>,
    /// Vault for secret storage + audit. Wired so the secrets MCP handlers
    /// can route through the same envelope-encryption + audit-log path
    /// the rest of the platform uses, instead of inlining `INSERT INTO
    /// secrets` SQL. CLAUDE.md priority extraction (was: "Blocked on
    /// wiring SecretsManager into McpState").
    ///
    /// Read by `handle_security_audit`, which runs the KEK wrap→unwrap
    /// self-test against the provider actually installed here. The migration
    /// of `mcp/secrets.rs::handle_*` still needs the name+namespace vs.
    /// key_path semantic mismatch reconciled first (see Pass 6 handoff) and
    /// remains a follow-up.
    pub secrets_manager: std::sync::Arc<talos_secrets_manager::SecretsManager>,
    /// Optional Ollama client for Tier 1 (local) LLM inference.
    /// Enabled when OLLAMA_URL is set (default: http://ollama:11434).
    pub ollama_client: Option<std::sync::Arc<talos_llm::OllamaClient>>,
    /// Runtime enforcer for `actor_approval_policies`. Wired into
    /// publish_version (and Phase 2: other call sites) so policies
    /// actually enforce instead of sitting inert in the DB.
    pub policy_evaluator: std::sync::Arc<talos_actor_policies::PolicyEvaluator>,
    /// Workflow-creation service. Owns the synchronous orchestration
    /// for `handle_create_workflow_from_description` (and, in time,
    /// the GraphQL `createWorkflowFromDescription` mutation). Pulled
    /// out of the 1,104-line MCP handler in 2026-05-04; the handler
    /// is now ~80 lines of protocol dressing + background-task spawn.
    pub workflow_creation_service: std::sync::Arc<talos_workflow_creation::WorkflowCreationService>,
    /// Hot-update orchestration. Owns the recompile-and-mirror flow that
    /// was previously inline in `handle_hot_update_module` (~530 LoC). The
    /// handler is now a thin wrapper that parses MCP args into
    /// `talos_hot_update_service::HotUpdateInput`, calls `execute`, and
    /// shapes the outcome back into a JSON-RPC response.
    pub hot_update_service: std::sync::Arc<talos_hot_update_service::HotUpdateService>,
    /// Execution-orchestration service. Owns trigger / replay /
    /// replay_with_input / retry. Same Arc is wired into the GraphQL
    /// schema so the `triggerWorkflow` mutation and the MCP
    /// `trigger_workflow` tool share one instance (one engine
    /// builder, one NATS dispatch path, one auth gate). Pulled out
    /// of ~1020 LoC across executions.rs + workflows.rs.
    pub execution_orchestration_service:
        std::sync::Arc<talos_execution_orchestration::ExecutionOrchestrationService>,
    /// Workflow manifest service — backs `import_platform_state` /
    /// `export_platform_state`. The handlers became thin wrappers in
    /// 2026-05-05; the orchestration (parallel fetches, module-UUID
    /// remap, dry-run preview, batched DB lookups) lives in
    /// `talos-workflow-manifest`. Cross-protocol-ready: the same Arc
    /// can back a future GraphQL mutation without duplicating logic.
    pub workflow_manifest_service: std::sync::Arc<talos_workflow_manifest::WorkflowManifestService>,
    /// Replay service — backs `replay_module_regression` (both module
    /// and workflow modes). Owns the load-with-template-fallback,
    /// secret prefetch, and per-row execute-and-diff kernel that was
    /// previously inline-duplicated across two ~340 LoC handlers.
    /// Cross-protocol-ready: typed input + outcome, `ReplayError`
    /// with stable `jsonrpc_code()` mapping.
    pub replay_service: std::sync::Arc<talos_replay_service::ReplayService>,
    /// Inline-Rust compile service — backs the `rust_code` branch of
    /// `add_node_to_workflow`. Owns the wrap → lint → compile → mirror
    /// flow plus the shared-module overwrite + permission-drift guards
    /// that were ~330 LoC of inline-handler logic. Cross-protocol-ready:
    /// typed input + outcome, `InlineCompileError` with stable
    /// `jsonrpc_code()` mapping.
    pub inline_compile_service: std::sync::Arc<talos_inline_compile_service::InlineCompileService>,
    /// Search service — backs `search_workflows_semantic`. Owns the
    /// fallback chain (caller embedding → auto-generate → vector →
    /// trigram → ILIKE) plus the embedding pipeline (config, rate-
    /// limited generator, provider health probe, pgvector formatting,
    /// fire-and-forget auto-embed). Cross-protocol-ready: typed
    /// input + outcome, `SearchError` with stable `jsonrpc_code()`
    /// mapping.
    pub search_service: std::sync::Arc<talos_search_service::SearchService>,
    /// Failure-analysis service — backs `analyze_execution_failure`.
    /// Owns the per-node error classification, remediation playbooks,
    /// and the config-field auto-fix write path (MCP-1227 chokepoint
    /// parity). Cross-protocol-ready: typed input + outcome,
    /// `FailureAnalysisError` with stable `jsonrpc_code()` mapping and
    /// generic-string DB error collapse.
    pub failure_analysis_service:
        std::sync::Arc<talos_failure_analysis_service::FailureAnalysisService>,
    /// Actor-lifecycle service — backs `scaffold_actor` and
    /// `handoff_to_actor` (plus the deprecated `handoff_to_agent`
    /// alias). Owns the scaffold arg-validation stack and the full
    /// handoff gate sequence + engine dispatch. Cross-protocol-ready:
    /// typed outcomes, `ScaffoldActorError` / `HandoffError` with
    /// stable `jsonrpc_code()` mappings.
    pub actor_lifecycle_service:
        std::sync::Arc<talos_actor_lifecycle_service::ActorLifecycleService>,
    /// Platform-hygiene service — backs `get_platform_hygiene_report`
    /// (report assembly + the fix_all dry-run/execute flow). Constructed
    /// in `create_router` from the shared repository Arcs (same wiring
    /// shape as `policy_evaluator`). Cross-protocol-ready: typed input +
    /// outcome, `HygieneError` with stable `jsonrpc_code()` mapping and
    /// generic-string internal-error collapse.
    pub hygiene_service: std::sync::Arc<talos_hygiene_service::HygieneService>,
    /// Session-brief service — backs `session_start` (and the deprecated
    /// `agent_session_start` alias). Owns the coverage / drafts /
    /// schedules / actors / recent-executions assembly; the handler keeps
    /// only protocol parsing, compile-time identity (env!-stamped
    /// version), and the auto-heal background spawns.
    pub session_brief_service: std::sync::Arc<talos_session_brief_service::SessionBriefService>,
    /// Judge-probe service — backs `probe_inline_judge`. Replays an
    /// inline-judge node's verdict against synthetic parent inputs through
    /// the engine's own binding / evaluation / envelope helpers, so an
    /// operator can answer the digest's "verify it in the FAILURE direction"
    /// instruction without firing the real workflow. A pure composition of
    /// one repository Arc, so it is constructed in-place here (same shape as
    /// `hygiene_service`). Cross-protocol-ready: typed input + outcome,
    /// `ProbeError` with stable `jsonrpc_code()` and a generic
    /// `user_facing_message()` for internal errors.
    pub judge_probe_service: std::sync::Arc<talos_judge_probe::JudgeProbeService>,
    /// Push-channel inventories, injected by the controller (2026-09-08).
    ///
    /// A trait-object SET rather than a dependency on `talos-gmail` /
    /// `talos-google-calendar` / `talos-google-cloud`: this crate sits BELOW
    /// them and the edge the other way is the layering inversion the 2026-09-07
    /// package refused to make. The newtype hides the `dyn`, following the
    /// `talos_dlp_provider::DlpService` precedent — this is the only field here
    /// backed by one.
    ///
    /// `None` means this process wired no inventory, and `list_push_channels`
    /// renders that as `not_measured` — never as an empty list.
    pub push_channels:
        Option<std::sync::Arc<talos_push_channel_inventory::PushChannelInventorySet>>,
}

pub fn create_router(
    registry: std::sync::Arc<ModuleRegistry>,
    db_pool: sqlx::PgPool,
    runtime: std::sync::Arc<talos_worker_runtime::runtime::TalosRuntime>,
    compiler: std::sync::Arc<CompilationService>,
    nats_client: Option<std::sync::Arc<async_nats::Client>>,
    llm_client: Option<std::sync::Arc<talos_llm::LlmClient>>,
    circuit_breaker: std::sync::Arc<talos_webhooks::CircuitBreaker>,
    dlp_service: std::sync::Arc<talos_dlp_provider::DlpService>,
    workflow_repo: std::sync::Arc<talos_workflow_repository::WorkflowRepository>,
    execution_repo: std::sync::Arc<talos_execution_repository::ExecutionRepository>,
    analytics_repo: std::sync::Arc<talos_analytics_repository::AnalyticsRepository>,
    advanced_repo: std::sync::Arc<talos_advanced_repository::AdvancedRepository>,
    actor_repo: std::sync::Arc<talos_actor_repository::ActorRepository>,
    module_repo: std::sync::Arc<talos_module_repository::ModuleRepository>,
    secrets_manager: std::sync::Arc<talos_secrets_manager::SecretsManager>,
    workflow_creation_service: std::sync::Arc<talos_workflow_creation::WorkflowCreationService>,
    hot_update_service: std::sync::Arc<talos_hot_update_service::HotUpdateService>,
    execution_orchestration_service: std::sync::Arc<
        talos_execution_orchestration::ExecutionOrchestrationService,
    >,
    workflow_manifest_service: std::sync::Arc<talos_workflow_manifest::WorkflowManifestService>,
    replay_service: std::sync::Arc<talos_replay_service::ReplayService>,
    inline_compile_service: std::sync::Arc<talos_inline_compile_service::InlineCompileService>,
    search_service: std::sync::Arc<talos_search_service::SearchService>,
    failure_analysis_service: std::sync::Arc<
        talos_failure_analysis_service::FailureAnalysisService,
    >,
    actor_lifecycle_service: std::sync::Arc<talos_actor_lifecycle_service::ActorLifecycleService>,
    // Ollama client for Tier 1 (local) LLM inference, constructed ONCE in
    // main() and shared with the automatic teacher-audit scheduler (one
    // reqwest pool). MCP-630 (2026-05-12): main() routes the URL through
    // `talos_config::get_env` so a Helm placeholder `ollamaUrl: ""` falls
    // through to the in-cluster default instead of a base-URL-less client.
    ollama_client: Option<std::sync::Arc<talos_llm::OllamaClient>>,
    // Built in `bootstrap/services.rs` from the three integration crates, which
    // only the controller bin may depend on. `None` is a real state and renders
    // as `not_measured`, so it is threaded rather than defaulted.
    push_channels: Option<std::sync::Arc<talos_push_channel_inventory::PushChannelInventorySet>>,
) -> Router {
    // Construct the actor-policy evaluator with the same repos the
    // MCP handlers use. The sweeper task is started below.
    let policy_evaluator = talos_actor_policies::PolicyEvaluator::new(
        db_pool.clone(),
        actor_repo.clone(),
        advanced_repo.clone(),
    );
    policy_evaluator.clone().spawn_sweeper();

    // Hygiene + session-brief services are pure compositions of the
    // repository Arcs already threaded in here, so they're constructed
    // in-place (same wiring shape as `policy_evaluator`) — no
    // controller/main.rs change required. If a GraphQL consumer appears,
    // lift construction to main.rs and thread the shared Arc through.
    let hygiene_service = std::sync::Arc::new(talos_hygiene_service::HygieneService::new(
        analytics_repo.clone(),
        workflow_repo.clone(),
        execution_repo.clone(),
        module_repo.clone(),
        push_channels.clone(),
    ));
    let session_brief_service = std::sync::Arc::new(
        talos_session_brief_service::SessionBriefService::new(advanced_repo.clone()),
    );
    let judge_probe_service = std::sync::Arc::new(talos_judge_probe::JudgeProbeService::new(
        advanced_repo.clone(),
    ));

    // The workflow-creation service is constructed in main.rs (so
    // GraphQL and MCP share one instance) and threaded in here.

    let state = McpState {
        db_pool: db_pool.clone(),
        registry,
        agent_channels: std::sync::Arc::new(DashMap::new()),
        runtime,
        compiler,
        nats_client,
        llm_client,
        circuit_breaker,
        dlp_service,
        workflow_repo,
        execution_repo,
        analytics_repo,
        advanced_repo,
        actor_repo,
        module_repo,
        secrets_manager,
        ollama_client,
        policy_evaluator,
        workflow_creation_service,
        hot_update_service,
        execution_orchestration_service,
        workflow_manifest_service,
        replay_service,
        inline_compile_service,
        search_service,
        failure_analysis_service,
        actor_lifecycle_service,
        hygiene_service,
        session_brief_service,
        judge_probe_service,
        push_channels,
    };

    // Authenticated routes (Bearer token required)
    let authenticated = Router::new()
        .route("/sse", get(sse_handler))
        .route("/message", post(message_handler))
        // Streamable HTTP: GET returns SSE keepalive, POST returns JSON-RPC response
        .route(
            "/",
            get(streamable_http_get_handler).post(streamable_http_handler),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            db_pool.clone(),
            auth::mcp_auth_middleware,
        ));

    // Local development route — NO auth required.
    // SECURITY: Only available when RUST_ENV != "production".
    // Uses a default admin agent identity for local development.
    let is_production = talos_config::is_production();

    if is_production {
        tracing::info!("MCP local endpoint DISABLED (production mode)");
        authenticated.with_state(state)
    } else {
        tracing::info!(
            "MCP local endpoint ENABLED (optimized build) at /mcp/local (development mode)"
        );
        let local_state = state.clone();
        let local_db = db_pool.clone();

        let local_route = Router::new().route(
            "/local",
            get(local_get_handler).post(move |Json(payload): Json<JsonRpcRequest>| {
                let state = local_state.clone();
                let db = local_db.clone();
                async move {
                    // JSON-RPC 2.0 §5: notifications (no `id`) must NOT receive a
                    // response body. Returning {"id":null,...} causes Zod validation
                    // failures in bridges that require id to be string|number, not null.
                    //
                    // Hoisted ABOVE the identity resolution on 2026-09-08: a
                    // notification needs no user, and the resolution below can now
                    // REFUSE, which must not put a body on a notification.
                    if payload.method.starts_with("notifications/") {
                        return axum::http::StatusCode::ACCEPTED.into_response();
                    }

                    // Resolve the local dev user: use the first registered user if
                    // one exists (preserves continuity when the web UI was used to
                    // register), otherwise create a synthetic dev user so that FK
                    // constraints always have a valid user_id.
                    //
                    // Both reads were swallowed (`.ok().flatten()`), and the comment
                    // that stood here NAMED the consequence without preventing it:
                    // "a fresh database leaves agent.user_id = None, causing every
                    // user-scoped INSERT to write NULL and every user-scoped SELECT
                    // to return zero rows — tools appear to succeed but nothing
                    // persists." That is the reported-success-on-a-failed-read class
                    // in its purest form, and it is worse than a claim in one field:
                    // EVERY tool on the endpoint then reports success while writing
                    // nowhere. `Ok(None)` from the first read is a genuinely fresh
                    // database and still falls through to creation; an `Err` from
                    // either read, or a creation that produced no user, now REFUSES
                    // the request instead of serving it identity-less.
                    let sysrepo = talos_system_repo::SystemRepository::new(db.clone());
                    let dev_user_id: uuid::Uuid = match sysrepo.find_first_user_id().await {
                        Ok(Some(existing)) => existing,
                        Ok(None) => {
                            tracing::info!(
                                "Fresh database — creating synthetic dev user for local MCP endpoint"
                            );
                            match sysrepo.ensure_dev_user().await {
                                Ok(Some(id)) => id,
                                other => {
                                    tracing::error!(
                                        event_kind = "local_dev_identity_unresolved",
                                        created = other.as_ref().map(Option::is_some).unwrap_or(false),
                                        error = other.as_ref().err().map(ToString::to_string),
                                        "MCP /local: could not provision the dev user; refusing rather than serving an identity-less request"
                                    );
                                    return Json(local_identity_refusal(payload.id)).into_response();
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                event_kind = "local_dev_identity_unresolved",
                                error = %e,
                                "MCP /local: could not read the user table; refusing rather than serving an identity-less request"
                            );
                            return Json(local_identity_refusal(payload.id)).into_response();
                        }
                    };

                    // Create a default local agent identity
                    let agent = std::sync::Arc::new(auth::AgentIdentity {
                        agent_id: uuid::Uuid::nil(),
                        name: "local-dev".to_string(),
                        role_name: "System Administrator".to_string(),
                        allowed_capabilities: vec!["*".to_string()],
                        user_id: Some(dev_user_id),
                    });

                    let response = match payload.method.as_str() {
                        "initialize" => handle_initialize(payload),
                        "tools/list" => {
                            handle_tools_list(payload)
                        }
                        "tools/call" => {
                            handle_tools_call(payload, state.clone(), agent.clone()).await
                        }
                        "resources/list" => {
                            handle_resources_list(payload, state.db_pool.clone(), agent.clone())
                                .await
                        }
                        "resources/read" => {
                            handle_resources_read(
                                payload,
                                state.db_pool.clone(),
                                state.execution_repo.clone(),
                                agent.clone(),
                            )
                            .await
                        }
                        _ => JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: payload.id,
                            result: None,
                            error: Some(JsonRpcError {
                                code: -32601,
                                message: "Method not found".to_string(),
                                data: None,
                            }),
                            error_kind: None,
                        },
                    };
                    Json(response).into_response()
                }
            }),
        );

        authenticated.merge(local_route).with_state(state)
    }
}

/// The `/mcp/local` refusal when no dev identity could be resolved.
///
/// A named constructor rather than an inline literal so the two call sites
/// above cannot drift: an identity-less request used to be SERVED, and every
/// tool it reached then reported success while writing nowhere.
fn local_identity_refusal(id: Option<serde_json::Value>) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(JsonRpcError {
            code: -32000,
            message: "Local dev identity could not be resolved, so this request was REFUSED \
                      rather than run without a user. Running it would have reported success \
                      while every user-scoped write landed nowhere. Check the database and \
                      retry."
                .to_string(),
            data: None,
        }),
        error_kind: None,
    }
}

/// Establish an SSE connection (acting as an MCP transport).
/// Includes periodic token revalidation to propagate session revocations.
async fn sse_handler(
    State(state): State<McpState>,
    axum::extract::Extension(agent): axum::extract::Extension<std::sync::Arc<auth::AgentIdentity>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // SECURITY: Create a per-agent broadcast channel so responses are isolated.
    let agent_key = agent.agent_id.to_string();
    let (tx, _) = broadcast::channel(100);
    state.agent_channels.insert(agent_key.clone(), tx.clone());
    let rx = tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|res| res.ok()).map(Ok);

    // Send notifications/tools/list_changed so MCP bridges (mcp-remote, etc.) that
    // cache tools/list will re-fetch. Fire at 3 s, 15 s, and 60 s to handle bridges
    // that miss the first notification due to connection setup latency.
    //
    // `params` MUST be OMITTED, never `null`: JSON-RPC 2.0 requires params to
    // be a structured value when present, and the MCP schema types it as an
    // optional OBJECT. Strict clients (mcp-remote's Zod validator, live
    // incident 2026-07-10) reject `"params": null` messages with a ZodError
    // on every notification — three per connection — which can break tool
    // registration in clients that treat stream errors as fatal. Same rule
    // applies to the two sibling emission sites below.
    let tx_notif = tx.clone();
    tokio::spawn(async move {
        for delay_secs in [3u64, 15, 60] {
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;
            let data = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed"
            });
            let event = Event::default().event("message").data(data.to_string());
            if tx_notif.send(event).is_err() {
                break; // client disconnected — stop sending
            }
        }
    });

    // Provide the initial `endpoint` event according to MCP spec
    let init_event = Event::default().event("endpoint").data("/mcp/message");

    let stream = futures::stream::once(async move { Ok(init_event) }).chain(stream);

    // SECURITY: Periodic token revalidation — terminates SSE if the agent token
    // has been revoked (is_active = false or record deleted).
    //
    // MCP-663 (2026-05-13): route through `positive_env_or_default` so a
    // misconfigured `MCP_TOKEN_REVALIDATION_INTERVAL_SECS=0` doesn't
    // produce a busy-loop revalidation tick (`tokio::time::interval(0)`
    // fires "as fast as possible" — would hammer the DB with revalidate
    // queries every microsecond per open SSE stream, exhausting the
    // pool). Same `=0` footgun class as MCP-638/639/640/642/643/661.
    let revalidation_interval_secs: u64 =
        talos_config::positive_env_or_default("MCP_TOKEN_REVALIDATION_INTERVAL_SECS", 60u64);

    let agent_id = agent.agent_id;
    let db_pool = state.db_pool.clone();

    // Create a stream that yields a "token_revoked" sentinel when the token becomes invalid.
    let agent_channels_revoke = state.agent_channels.clone();
    let agent_key_revoke = agent_key.clone();
    let revocation_stream = async_stream::stream! {
        let mut interval = tokio::time::interval(Duration::from_secs(revalidation_interval_secs));
        // Skip the initial immediate tick
        interval.tick().await;

        loop {
            interval.tick().await;

            // Re-check agent validity in the database
            let sysrepo = talos_system_repo::SystemRepository::new(db_pool.clone());
            let is_valid = sysrepo.is_agent_active(agent_id).await;

            if !is_valid {
                tracing::warn!(
                    agent_id = %agent_id,
                    "MCP session revocation detected — closing SSE stream"
                );
                // Clean up agent channel on revocation
                agent_channels_revoke.remove(&agent_key_revoke);
                // Yield a termination event and break
                yield Ok(Event::default()
                    .event("error")
                    .data("Session revoked: agent token is no longer valid"));
                break;
            }
        }
    };

    // Merge the main SSE stream with the revocation check stream.
    // The SSE stream terminates when either the normal stream ends or a revocation is detected.
    // Pin both streams since `select` requires `Unpin`.
    let stream = Box::pin(stream);
    let revocation_stream = Box::pin(revocation_stream);
    let merged_stream = futures::stream::select(stream, revocation_stream);

    // MCP-699 (2026-05-13): Drop-impl guard for the agent_channels entry.
    // Pre-fix the cleanup line `agent_channels_drop.remove(&agent_key_drop)`
    // lived *after* the `while let Some(item)` loop inside an
    // `async_stream::stream!` macro. That code only executes when the
    // loop exits naturally (stream end) or via revocation (covered by
    // the explicit remove() inside revocation_stream). When the SSE
    // client disconnects abruptly — the common case for browser
    // refresh, network hiccup, mcp-remote restart — axum drops the
    // response body, which drops the async_stream task, which destroys
    // the generator state without executing the cleanup line. The
    // broadcast::Sender stays in agent_channels forever. Per-agent
    // ~120 bytes (key String + Sender + Arc overhead); over a long-
    // running pod hosting many distinct agent identities, the leak
    // accumulates monotonically. The guard's `Drop` impl runs
    // unconditionally — on natural end, on revocation, AND on abrupt
    // disconnect — so the DashMap entry is cleaned up in every exit
    // path. Pattern same as MCP-694 governor cleanup + MCP-690 audit
    // parity: explicit eviction on every exit edge, not just the
    // happy path. (The double-remove on natural-end + revocation is
    // harmless — DashMap::remove on a missing key is a no-op.)
    struct AgentChannelGuard {
        channels: std::sync::Arc<DashMap<String, broadcast::Sender<Event>>>,
        key: String,
    }
    impl Drop for AgentChannelGuard {
        fn drop(&mut self) {
            self.channels.remove(&self.key);
        }
    }
    let cleanup_guard = AgentChannelGuard {
        channels: state.agent_channels.clone(),
        key: agent_key,
    };
    let cleanup_stream = async_stream::stream! {
        // Move the guard into the generator so its Drop runs on
        // stream-drop (abrupt disconnect) AND on natural end.
        let _guard = cleanup_guard;
        let mut inner = Box::pin(merged_stream);
        while let Some(item) = futures::StreamExt::next(&mut inner).await {
            yield item;
        }
        // _guard drops here on natural end.
    };

    Sse::new(cleanup_stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

/// Accept JSON-RPC messages from the MCP client.
async fn message_handler(
    State(state): State<McpState>,
    axum::extract::Extension(agent): axum::extract::Extension<std::sync::Arc<auth::AgentIdentity>>,
    Json(payload): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    // SECURITY: Two-layer rate limiting.
    //   Layer 1 — per-agent: prevents a single runaway agent from flooding the API.
    //   Layer 2 — per-user: prevents bypass via multiple agents (N agents × per-agent
    //             limit = N× effective rate without this check).
    let agent_allowed = AGENT_RATE_LIMITER.check_and_increment(&agent.agent_id.to_string());
    let user_allowed = agent
        .user_id
        .map(|uid| USER_RATE_LIMITER.check_and_increment(&uid.to_string()))
        .unwrap_or(true); // Agents without a user_id are system agents — exempt.
    if !agent_allowed || !user_allowed {
        let limit_type = if !agent_allowed { "agent" } else { "user" };
        tracing::warn!(
            agent_id = %agent.agent_id,
            agent_name = %agent.name,
            limit_type,
            "MCP rate limit exceeded"
        );
        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: payload.id,
            result: None,
            error: Some(JsonRpcError {
                code: -32029, // Rate limited
                message: "Rate limit exceeded: too many requests per minute for this agent"
                    .to_string(),
                data: None,
            }),
            error_kind: None,
        };
        // Send rate-limited response via SSE to this agent only
        {
            let json_str = utils::mcp_serialize(&response);
            let event = Event::default().event("message").data(json_str);
            if let Some(sender) = state.agent_channels.get(&agent.agent_id.to_string()) {
                let _ = sender.send(event);
            }
        }
        return axum::http::StatusCode::TOO_MANY_REQUESTS;
    }

    let response = match payload.method.as_str() {
        "initialize" => handle_initialize(payload),
        "tools/list" => handle_tools_list(payload),
        "tools/call" => handle_tools_call(payload, state.clone(), agent.clone()).await,
        "resources/list" => {
            handle_resources_list(payload, state.db_pool.clone(), agent.clone()).await
        }
        "resources/read" => {
            handle_resources_read(
                payload,
                state.db_pool.clone(),
                state.execution_repo.clone(),
                agent.clone(),
            )
            .await
        }
        _ => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: payload.id,
            result: None,
            error: Some(JsonRpcError {
                code: -32601, // Method not found
                message: "Method not found".to_string(),
                data: None,
            }),
            error_kind: None,
        },
    };

    // Send response back via SSE to this agent only
    {
        let json_str = utils::mcp_serialize(&response);
        let event = Event::default().event("message").data(json_str);
        if let Some(sender) = state.agent_channels.get(&agent.agent_id.to_string()) {
            let _ = sender.send(event);
        }
    }

    // Acknowledge the POST
    axum::http::StatusCode::ACCEPTED
}

/// Streamable HTTP handler for Claude Desktop and other MCP clients that expect
/// a synchronous JSON-RPC response from a POST request (MCP Streamable HTTP transport).
///
/// Unlike the SSE+POST pattern above, this returns the response directly in the
/// HTTP response body with `Content-Type: application/json`.
async fn streamable_http_handler(
    State(state): State<McpState>,
    axum::extract::Extension(agent): axum::extract::Extension<std::sync::Arc<auth::AgentIdentity>>,
    Json(payload): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    // Rate limit — same two-layer check as message_handler
    let agent_allowed = AGENT_RATE_LIMITER.check_and_increment(&agent.agent_id.to_string());
    let user_allowed = agent
        .user_id
        .map(|uid| USER_RATE_LIMITER.check_and_increment(&uid.to_string()))
        .unwrap_or(true);
    if !agent_allowed || !user_allowed {
        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: payload.id,
            result: None,
            error: Some(JsonRpcError {
                code: -32029,
                message: "Rate limit exceeded".to_string(),
                data: None,
            }),
            error_kind: None,
        };
        return (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            utils::mcp_serialize(&response),
        )
            .into_response();
    }

    // JSON-RPC 2.0 §5: notifications (no `id`) must NOT receive a response body.
    // Returning {"id":null,"result":{}} would cause Zod validation failures in
    // bridges (e.g. @nimbletools/mcp-http-bridge) that parse every HTTP response
    // as a JSON-RPC message and require id to be string|number, not null.
    if payload.method.starts_with("notifications/") {
        return axum::http::StatusCode::ACCEPTED.into_response();
    }

    // Dispatch to the same handlers used by the SSE path
    let response = match payload.method.as_str() {
        "initialize" => handle_initialize(payload),
        "tools/list" => handle_tools_list(payload),
        "tools/call" => handle_tools_call(payload, state.clone(), agent.clone()).await,
        "resources/list" => {
            handle_resources_list(payload, state.db_pool.clone(), agent.clone()).await
        }
        "resources/read" => {
            handle_resources_read(
                payload,
                state.db_pool.clone(),
                state.execution_repo.clone(),
                agent.clone(),
            )
            .await
        }
        _ => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: payload.id,
            result: None,
            error: Some(JsonRpcError {
                code: -32601,
                message: "Method not found".to_string(),
                data: None,
            }),
            error_kind: None,
        },
    };

    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        utils::mcp_serialize(&response),
    )
        .into_response()
}

/// GET handler for Streamable HTTP transport.
/// Returns an SSE stream with keepalive pings. Claude Desktop sends GET to
/// establish the server-to-client event channel before POST-ing JSON-RPC.
/// Also sends notifications/tools/list_changed so mcp-remote and other
/// bridges that cache tools/list will re-fetch after connection setup.
async fn streamable_http_get_handler(
    State(_state): State<McpState>,
    axum::extract::Extension(_agent): axum::extract::Extension<std::sync::Arc<auth::AgentIdentity>>,
) -> impl IntoResponse {
    let stream = async_stream::stream! {
        // Notify bridges to re-fetch tools/list. Fire at 3 s, 15 s, and 60 s
        // to reach bridges that miss earlier notifications due to setup latency.
        for delay_secs in [3u64, 15, 60] {
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;
            let data = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed"
            });
            yield Ok::<_, Infallible>(
                Event::default().event("message").data(data.to_string())
            );
        }
        // The tool list is fixed for the life of the process (2026-10-03),
        // so nothing follows but keepalives.
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            yield Ok::<_, Infallible>(Event::default().comment("keepalive"));
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

/// GET handler for the local (unauthenticated) endpoint.
/// Returns an SSE stream for server-initiated messages (Streamable HTTP transport).
/// Sends notifications/tools/list_changed so mcp-remote caches are cleared and
/// the full tool list is fetched on every reconnect.
async fn local_get_handler() -> impl IntoResponse {
    let stream = async_stream::stream! {
        // Notify bridges to re-fetch tools/list. Fire at 3 s, 15 s, and 60 s
        // to reach bridges that miss earlier notifications due to setup latency.
        for delay_secs in [3u64, 15, 60] {
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;
            let data = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed"
            });
            yield Ok::<_, Infallible>(
                Event::default().event("message").data(data.to_string())
            );
        }
        // The tool list is fixed for the life of the process (2026-10-03),
        // so nothing follows but keepalives.
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            yield Ok::<_, Infallible>(Event::default().comment("keepalive"));
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

// -----------------------------------------------------------------------------
// Message Handlers
// -----------------------------------------------------------------------------

/// Canonical count of static (non-catalog) MCP tool schemas registered by the
/// controller. Single source of truth shared between `handle_initialize`
/// (which surfaces the number in the MCP `instructions` blob) and
/// `handle_get_platform_info` (which surfaces it as `total_mcp_tools`).
///
/// Before unification these two sites maintained independent lists that drifted
/// — `handle_get_platform_info` forgot to include `knowledge_graph` and
/// `ollama`, producing a count 8 smaller than `handle_initialize`. Routing
/// both callers through this function makes a future divergence impossible.
pub(crate) fn static_tool_count() -> usize {
    static COUNT: std::sync::LazyLock<usize> = std::sync::LazyLock::new(|| {
        advanced::tool_schemas().len()
            + platform::tool_schemas().len()
            + search::tool_schemas().len()
            + workflows::tool_schemas().len()
            + modules::tool_schemas().len()
            + sandbox::tool_schemas().len()
            + executions::tool_schemas().len()
            + actor::tool_schemas().len()
            + analytics::tool_schemas().len()
            + secrets::tool_schemas().len()
            + schedules::tool_schemas().len()
            + versions::tool_schemas().len()
            + webhooks::tool_schemas().len()
            + graph::tool_schemas().len()
            + knowledge_graph::tool_schemas().len()
            + alerts::tool_schemas().len()
            + ops_alerts::tool_schemas().len()
            + schemas::tool_schemas().len()
            + ollama::tool_schemas().len()
            + ml::tool_schemas().len()
            + evaluation::tool_schemas().len()
    });
    *COUNT
}

/// MCP spec versions this server supports, newest → oldest.
/// During `initialize`, the server echoes the client's requested version when
/// listed here; otherwise falls back to the newest (first) entry per the spec
/// (https://spec.modelcontextprotocol.io/specification/2025-03-26/basic/lifecycle/).
/// The controller exposes both legacy HTTP+SSE (/mcp/sse + /mcp/message) and
/// 2025-03-26 Streamable HTTP (/mcp GET+POST), so all listed versions are live.
const SUPPORTED_MCP_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

pub(crate) fn handle_initialize(req: JsonRpcRequest) -> JsonRpcResponse {
    let version = env!("CARGO_PKG_VERSION");

    // Echo the client's requested protocolVersion when we support it; otherwise
    // fall back to the newest version we support. Modern clients (Claude Code
    // 2025+) request 2025-03-26 or 2025-06-18; hardcoding "2024-11-05" caused
    // them to dead-end even though the Streamable HTTP transport is live. See
    // https://spec.modelcontextprotocol.io/specification/2025-03-26/basic/lifecycle/.
    let requested: Option<&str> = req
        .params
        .as_ref()
        .and_then(|p| p.get("protocolVersion"))
        .and_then(|v| v.as_str());
    let negotiated_version: &str = match requested {
        Some(v) if SUPPORTED_MCP_PROTOCOL_VERSIONS.contains(&v) => v,
        _ => SUPPORTED_MCP_PROTOCOL_VERSIONS[0],
    };

    let instructions = format!(
        "This is the Talos workflow-automation platform. Server version: {}. \
         It has {} tools. Catalog modules are not tools: find one with list_module_catalog and \
         install it with install_module_from_catalog. \
         SCHEMA FRESHNESS: Call session_start() at the beginning of every session. \
         It returns the current server version under 'server_version'. If this differs from \
         what your cached tools/list shows, your schema is stale — reconnect or call tools/list again. \
         TOOL DISCOVERY: If any tool call fails with 'not found', 'not loaded', 'unknown tool', \
         or 'parameter names are wrong': \
         (1) Do NOT assume the parameter names are incorrect. \
         (2) Call tool_search(query: \"<relevant keyword>\") to find the correct tool name, \
         then retry. Example: 'schedule_wf' fails → tool_search(query: \"schedule\") → use 'create_schedule'. \
         SYNCHRONOUS EXECUTION: Use call_workflow (not trigger_workflow) when you need the result inline. \
         trigger_workflow is async and returns only an execution_id.",
        version,
        static_tool_count(),
    );
    let result = serde_json::json!({
        "protocolVersion": negotiated_version,
        "serverInfo": {
            "name": "Talos Native MCP Server",
            "version": version
        },
        "capabilities": {
            "tools": { "listChanged": true },
            "resources": {}
        },
        // Injected into the LLM's system prompt by MCP clients that support this field.
        // This surfaces the correct recovery action regardless of what error the client
        // proxy (e.g. mcp-remote) generates for tools that aren't in its local cache.
        "instructions": instructions,
    });

    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: req.id,
        result: Some(result),
        error: None,
        error_kind: None,
    }
}

async fn handle_resources_list(
    req: JsonRpcRequest,
    db_pool: sqlx::PgPool,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    resources::handle_resources_list(req, db_pool, agent).await
}

async fn handle_resources_read(
    req: JsonRpcRequest,
    db_pool: sqlx::PgPool,
    execution_repo: std::sync::Arc<talos_execution_repository::ExecutionRepository>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    resources::handle_resources_read(req, db_pool, execution_repo, agent).await
}

/// `tools/list`: the static tools, and nothing else.
///
/// Until 2026-10-03 the reply also carried one tool per catalog module
/// (`<Name>-v1`), each an install shortcut whose input schema was the
/// module's config. Measured on the reference deployment: 98 of 456 tools
/// and 166 KB of a 549 KB reply (about 41,000 tokens of 137,000), read by
/// every client at every connect, to offer what two static tools already
/// do — `list_module_catalog` finds a module and `install_module_from_catalog`
/// installs it. 22 of the 98 were not catalog modules at all (a caller's own
/// modules outside the `sandbox` category); calling one failed.
///
/// With them gone the reply no longer depends on the caller or the database:
/// no catalog read per `tools/list`, and no reason to tell connected clients
/// the list changed when a module is installed, renamed or deleted.
///
/// Returned whole, with no pagination: MCP pagination is optional, most
/// clients do not follow `nextCursor`, and a paginated list silently hides
/// tools from a client that issues one request.
///
/// Order is by priority, meta and discovery tools first, so a client that
/// truncates by position keeps `session_start`, `get_platform_info` and
/// `tool_search`. The order is `tool_hints::all_static_schema_modules`'s.
fn handle_tools_list(req: JsonRpcRequest) -> JsonRpcResponse {
    static TOOLS: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
        let tools: Vec<serde_json::Value> = tool_hints::all_static_schema_modules()
            .into_iter()
            .flat_map(|(_module, schemas)| schemas)
            .collect();
        serde_json::json!({ "tools": tools })
    });
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: req.id,
        result: Some(TOOLS.clone()),
        error: None,
        error_kind: None,
    }
}

/// The catalog slug a retired `<Name>-v1` shortcut stood for, when `name`
/// has that shape: the suffix removed, lower-cased, underscores to hyphens,
/// runs of hyphens collapsed (`Stripe__Create_Customer-v1` →
/// `stripe-create-customer`).
fn retired_catalog_shortcut(name: &str) -> Option<String> {
    let sanitized = name.strip_suffix("-v1")?;
    let raw = sanitized.to_lowercase().replace('_', "-");
    let slug = raw
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    (!slug.is_empty()).then_some(slug)
}

/// The ONE `tools/call` chokepoint, and the ONE observation point for the
/// MCP surface.
///
/// Every transport reaches a tool through here — the Streamable-HTTP POST,
/// the SSE message endpoint and the local development endpoint all route
/// `"tools/call"` to this function and nothing else does dispatch — so a
/// measurement taken here covers the whole surface, and a NEW transport
/// inherits it without a second edit. That is the property the instrument
/// rests on; the dispatch itself is a chain of 21 domain `dispatch`
/// functions, each an `Option`-returning `match` over its own tool names, so
/// there is no single table to hang a measurement off further in.
///
/// The instrument OBSERVES and never alters: `inner` produces the response,
/// this wrapper reads its shape and returns it unchanged. Measured in a
/// release build over 200 000 iterations: **619 ns** for the whole wrapper
/// (label lookup + request-id render + `Instant` + classify + record + one
/// formatted INFO line), of which **108 ns** is everything except the log
/// line and **40 ns** is the label lookup alone. The fastest tool on this
/// surface (`whoami`) measures **2.3 ms**, so the instrument is **0.027 %**
/// of it; the slowest measured (`get_platform_hygiene_report`, 189 ms) is
/// five orders of magnitude above it.
pub async fn handle_tools_call(
    req: JsonRpcRequest,
    state: McpState,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    // Resolved BEFORE dispatch and from the static registry only — never the
    // caller's own string. See `tool_labels` for why.
    let tool = crate::tool_labels::canonical_tool_label(
        req.params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or(""),
    );
    let request_id = crate::tool_labels::request_id_field(req.id.as_ref());

    let started = std::time::Instant::now();
    let response = handle_tools_call_inner(req, state, agent).await;
    let elapsed = started.elapsed();

    let outcome = crate::tool_labels::classify_outcome(&response);
    talos_metrics::record_mcp_tool_call(tool, outcome, elapsed);

    // ONE structured line per call. `tool`, `outcome`, `class`,
    // `duration_ms` and the request id ONLY: never the arguments, never the
    // response, never a token. The arguments are the caller's payload and
    // this line reaches container stdout, which is as public as the log
    // pipeline that ships it.
    //
    // The MESSAGE is "MCP tool call", not "MCP tool call served": the live
    // line for this fleet's first refusal read `"MCP tool call served" …
    // outcome="error"`, i.e. fixed prose asserting the call was served next
    // to a field saying it was not. Same defect as this package's subject,
    // one field over. `class` rides beside `outcome` for the same reason it
    // rides on the metric — it is what an operator greps when the question is
    // "is the platform declining, or failing?".
    tracing::info!(
        target: "talos_mcp",
        event_kind = "mcp_tool_call",
        tool,
        outcome = outcome.as_str(),
        class = outcome.class().as_str(),
        duration_ms = elapsed.as_secs_f64() * 1000.0,
        request_id = %request_id,
        "MCP tool call"
    );

    response
}

async fn handle_tools_call_inner(
    req: JsonRpcRequest,
    state: McpState,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let name = req
        .params
        .as_ref()
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("");

    let args = req
        .params
        .as_ref()
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    // Unknown-argument detection (see utils::unknown_argument_warning):
    // arguments the tool's advertised schema doesn't declare are silently
    // ignored by handlers — a typo'd param name is an invisible no-op
    // (sweep finding: `depends_on` vs `connect_from` produced a
    // disconnected-but-"working" workflow). Warn, don't reject: a warning
    // catches caller typos AND schema under-declaration without turning
    // either into a hard failure. Names only in the log — never values.
    let arg_warning = crate::utils::unknown_argument_warning(name, &args);
    if let Some(w) = arg_warning.as_deref() {
        tracing::warn!(
            target: "talos_mcp",
            event_kind = "unknown_tool_arguments",
            tool = name,
            warning = w,
            "tools/call received argument names not in the tool's inputSchema"
        );
    }
    // The sibling check: a declared argument passed as the wrong JSON type is
    // read as absent by the handler (see utils::mistyped_argument_warning).
    let type_warning = crate::utils::mistyped_argument_warning(name, &args);
    if let Some(w) = type_warning.as_deref() {
        tracing::warn!(
            target: "talos_mcp",
            event_kind = "mistyped_tool_arguments",
            tool = name,
            warning = w,
            "tools/call received an argument whose JSON type is not the declared one"
        );
    }
    // Decorator applied to whichever domain dispatch claims the tool.
    let decorate = |mut r: JsonRpcResponse| -> JsonRpcResponse {
        // Says what a `[REDACTED:…]` marker in the result does and does not mean.
        crate::utils::append_redaction_notice(&mut r);
        if let Some(w) = arg_warning.as_deref() {
            crate::utils::append_warning_block(&mut r, w);
        }
        if let Some(w) = type_warning.as_deref() {
            crate::utils::append_warning_block(&mut r, w);
        }
        r
    };

    if let Some(r) = sandbox::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return decorate(r);
    }
    if let Some(r) = workflows::dispatch(
        name,
        req.id.clone(),
        &args,
        std::sync::Arc::new(state.clone()),
        agent.clone(),
    )
    .await
    {
        return decorate(r);
    }
    if let Some(r) = executions::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await
    {
        return decorate(r);
    }
    if let Some(r) = secrets::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return decorate(r);
    }
    if let Some(r) = schedules::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return decorate(r);
    }
    if let Some(r) = versions::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return decorate(r);
    }
    if let Some(r) = webhooks::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return decorate(r);
    }
    if let Some(r) = graph::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return decorate(r);
    }
    if let Some(r) = modules::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return decorate(r);
    }
    if let Some(r) = analytics::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return decorate(r);
    }
    if let Some(r) = search::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return decorate(r);
    }
    if let Some(r) = alerts::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return decorate(r);
    }
    if let Some(r) = ops_alerts::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await
    {
        return decorate(r);
    }
    if let Some(r) =
        knowledge_graph::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await
    {
        return decorate(r);
    }
    if let Some(r) =
        configuration::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await
    {
        return decorate(r);
    }
    if let Some(r) = platform::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return decorate(r);
    }
    if let Some(r) = advanced::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return decorate(r);
    }
    if let Some(r) = actor::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return decorate(r);
    }
    if let Some(r) = ollama::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return decorate(r);
    }
    if let Some(r) = ml::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return decorate(r);
    }
    if let Some(r) = evaluation::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await
    {
        return decorate(r);
    }

    // A `<Name>-v1` name was a catalog install shortcut until 2026-10-03.
    // A client holding a tool list from before then can still call one: it
    // is told what replaced it rather than only that the name is unknown.
    // Nothing is installed from here — `install_module_from_catalog` is the
    // one route, with its own arguments, grants and audit record.
    if let Some(slug) = retired_catalog_shortcut(name) {
        return mcp_error(
            req.id,
            -32601,
            &format!(
                "'{name}' is not a tool: catalog install shortcuts are no longer listed. \
                 Call install_module_from_catalog(name: \"{slug}\") to install that module, or \
                 list_module_catalog(query: \"…\") to find one and see whether it needs \
                 installing at all."
            ),
        );
    }

    // -32601 = MethodNotFound per JSON-RPC 2.0.
    // Message is deliberately actionable: the LLM should call tool_search to
    // discover the correct name rather than guess that parameter names are wrong.
    mcp_error(
        req.id,
        -32601,
        &format!(
            "Unknown tool: '{name}'. \
         The tool name may be misspelled, or this is a domain-specific tool that must be \
         discovered first. Call tool_search with a keyword (e.g. tool_search(query: \"schedule\")) \
         to find the correct tool name. Do NOT assume the parameter names are wrong — the tool \
         name itself is the issue."
        ),
    )
}

#[cfg(test)]
mod static_tool_list_tests {
    use super::*;

    fn listed() -> Vec<serde_json::Value> {
        let reply = handle_tools_list(JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            method: "tools/list".to_string(),
            params: None,
        });
        reply.result.expect("a result")["tools"]
            .as_array()
            .expect("tools")
            .clone()
    }

    /// The reply is the static tools: every one, once, and no catalog
    /// shortcut. It needs no database and no caller, which is the point.
    #[test]
    fn the_tool_list_is_the_static_tools_and_nothing_else() {
        let tools = listed();
        assert_eq!(tools.len(), static_tool_count());
        let names: Vec<&str> = tools
            .iter()
            .map(|t| t["name"].as_str().expect("a name"))
            .collect();
        let unique: std::collections::BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(unique.len(), names.len(), "a tool name is listed twice");
        let shortcuts: Vec<&&str> = names
            .iter()
            .filter(|n| retired_catalog_shortcut(n).is_some())
            .collect();
        assert!(
            shortcuts.is_empty(),
            "catalog shortcuts are listed again: {shortcuts:?}"
        );
        // What replaced them is there.
        for needed in [
            "list_module_catalog",
            "install_module_from_catalog",
            "get_module_info",
        ] {
            assert!(names.contains(&needed), "{needed} is not listed");
        }
        // Meta tools first, for a client that truncates by position.
        assert_eq!(names[0], "session_start");
        assert_eq!(listed(), tools, "two calls give one list");
    }

    #[test]
    fn a_retired_shortcut_names_the_slug_it_stood_for() {
        assert_eq!(
            retired_catalog_shortcut("HTTP_Request-v1").as_deref(),
            Some("http-request")
        );
        assert_eq!(
            retired_catalog_shortcut("Stripe__Create_Customer-v1").as_deref(),
            Some("stripe-create-customer")
        );
        assert_eq!(
            retired_catalog_shortcut("Send_HTML_Email__Gmail_-v1").as_deref(),
            Some("send-html-email-gmail")
        );
        // Not that shape: an ordinary unknown name gets the ordinary answer.
        for name in ["create_workflow", "schedule_wf", "-v1", "__-v1", "Thing-v2"] {
            assert_eq!(retired_catalog_shortcut(name), None, "{name}");
        }
        // No static tool has the shape, so none is shadowed by the refusal.
        for (_module, schemas) in tool_hints::all_static_schema_modules() {
            for schema in schemas {
                let name = schema["name"].as_str().expect("a name");
                assert_eq!(retired_catalog_shortcut(name), None, "{name}");
            }
        }
    }
}
