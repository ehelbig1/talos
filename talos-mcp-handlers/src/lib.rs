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
pub mod configuration;
pub mod executions;
pub mod graph;
pub mod knowledge_graph;
pub mod modules;
pub mod ollama;
pub mod platform;
pub mod resources;
pub mod sandbox;
pub mod schedules;
pub mod schemas;
pub mod search;
pub mod secrets;
pub mod ssrf_resolver;
pub mod types;
pub mod utils;
pub mod versions;
pub mod webhooks;
pub mod workflows;

#[cfg(test)]
mod tests;

// ============================================================================
// Utility functions (re-exported from utils submodule)
// ============================================================================

use utils::{mcp_error, sanitize_tool_name};

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
    pub runtime: std::sync::Arc<worker::runtime::TalosRuntime>,
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
    /// Intentionally not yet read by any handler — the migration of
    /// `mcp/secrets.rs::handle_*` requires reconciling the name+namespace
    /// vs. key_path semantic mismatch first (see Pass 6 handoff). Field
    /// is reserved for that follow-up.
    #[allow(dead_code)]
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
    pub workflow_manifest_service:
        std::sync::Arc<talos_workflow_manifest::WorkflowManifestService>,
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
    pub inline_compile_service:
        std::sync::Arc<talos_inline_compile_service::InlineCompileService>,
    /// Search service — backs `search_workflows_semantic`. Owns the
    /// fallback chain (caller embedding → auto-generate → vector →
    /// trigram → ILIKE) plus the embedding pipeline (config, rate-
    /// limited generator, provider health probe, pgvector formatting,
    /// fire-and-forget auto-embed). Cross-protocol-ready: typed
    /// input + outcome, `SearchError` with stable `jsonrpc_code()`
    /// mapping.
    pub search_service: std::sync::Arc<talos_search_service::SearchService>,
}

pub fn create_router(
    registry: std::sync::Arc<ModuleRegistry>,
    db_pool: sqlx::PgPool,
    runtime: std::sync::Arc<worker::runtime::TalosRuntime>,
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
    workflow_manifest_service: std::sync::Arc<
        talos_workflow_manifest::WorkflowManifestService,
    >,
    replay_service: std::sync::Arc<talos_replay_service::ReplayService>,
    inline_compile_service: std::sync::Arc<
        talos_inline_compile_service::InlineCompileService,
    >,
    search_service: std::sync::Arc<talos_search_service::SearchService>,
) -> Router {
    // Initialize Ollama client for Tier 1 (local) LLM inference.
    // MCP-630 (2026-05-12): route through `talos_config::get_env` so a
    // Helm placeholder `ollamaUrl: ""` is treated as "unset" and falls
    // through to the in-cluster default. Pre-fix the bare
    // `unwrap_or_else(|_| default)` returned `""`, producing a
    // base-URL-less `format!("{}/v1/chat/completions", "")` that
    // failed at request time with a confusing url-parse error instead
    // of using the default. Sibling to MCP-615/620/621/623.
    let ollama_url = talos_config::get_env("OLLAMA_URL", "http://ollama:11434");
    let ollama_client = Some(std::sync::Arc::new(talos_llm::OllamaClient::new(
        ollama_url,
    )));

    // Construct the actor-policy evaluator with the same repos the
    // MCP handlers use. The sweeper task is started below.
    let policy_evaluator = talos_actor_policies::PolicyEvaluator::new(
        db_pool.clone(),
        actor_repo.clone(),
        advanced_repo.clone(),
    );
    policy_evaluator.clone().spawn_sweeper();

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
                    // Resolve the local dev user: use the first registered user if
                    // one exists (preserves continuity when the web UI was used to
                    // register), otherwise create a synthetic dev user so that FK
                    // constraints always have a valid user_id.  Without this, a fresh
                    // database leaves agent.user_id = None, causing every
                    // user-scoped INSERT to write NULL and every user-scoped SELECT to
                    // return zero rows — tools appear to succeed but nothing persists.
                    let dev_user_id: Option<uuid::Uuid> = {
                        let sysrepo = talos_system_repo::SystemRepository::new(db.clone());
                        let existing = sysrepo.find_first_user_id().await.ok().flatten();

                        if existing.is_some() {
                            existing
                        } else {
                            tracing::info!(
                                "Fresh database — creating synthetic dev user for local MCP endpoint"
                            );
                            sysrepo.ensure_dev_user().await.ok().flatten()
                        }
                    };

                    // Create a default local agent identity
                    let agent = std::sync::Arc::new(auth::AgentIdentity {
                        agent_id: uuid::Uuid::nil(),
                        name: "local-dev".to_string(),
                        role_name: "System Administrator".to_string(),
                        allowed_capabilities: vec!["*".to_string()],
                        user_id: dev_user_id,
                    });

                    // JSON-RPC 2.0 §5: notifications (no `id`) must NOT receive a
                    // response body. Returning {"id":null,...} causes Zod validation
                    // failures in bridges that require id to be string|number, not null.
                    if payload.method.starts_with("notifications/") {
                        return axum::http::StatusCode::ACCEPTED.into_response();
                    }

                    let response = match payload.method.as_str() {
                        "initialize" => handle_initialize(payload),
                        "tools/list" => {
                            handle_tools_list(payload, state.registry.clone(), agent.clone()).await
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
                        },
                    };
                    Json(response).into_response()
                }
            }),
        );

        authenticated.merge(local_route).with_state(state)
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
    let tx_notif = tx.clone();
    tokio::spawn(async move {
        for delay_secs in [3u64, 15, 60] {
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;
            let data = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed",
                "params": null
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
        "tools/list" => handle_tools_list(payload, state.registry.clone(), agent.clone()).await,
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
        "tools/list" => handle_tools_list(payload, state.registry.clone(), agent.clone()).await,
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
                "method": "notifications/tools/list_changed",
                "params": null
            });
            yield Ok::<_, Infallible>(
                Event::default().event("message").data(data.to_string())
            );
        }
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
                "method": "notifications/tools/list_changed",
                "params": null
            });
            yield Ok::<_, Infallible>(
                Event::default().event("message").data(data.to_string())
            );
        }
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
            + schemas::tool_schemas().len()
            + ollama::tool_schemas().len()
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
         It has {}+ tools (plus dynamically registered catalog templates). \
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

async fn handle_tools_list(
    req: JsonRpcRequest,
    registry: std::sync::Arc<ModuleRegistry>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let templates: Vec<talos_registry::NodeTemplate> = match registry.list_templates(None).await {
        Ok(t) => t,
        Err(e) => {
            // MCP-337 (2026-05-11): pre-fix the error response embedded
            // the raw `e: anyhow::Error` from registry.list_templates
            // — sqlx/Postgres errors can carry connection strings,
            // schema names, and the failing query text. Same MCP-217
            // redaction family as the Ollama handlers. Log the full
            // error server-side; return a generic message to the
            // caller.
            tracing::error!(
                target: "talos_mcp",
                event_kind = "tools_list_db_error",
                error = ?e,
                "list_templates query failed"
            );
            return JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32000,
                    message: "Database error: failed to list catalog templates (see controller logs)"
                        .to_string(),
                    data: None,
                }),
            };
        }
    };

    // Local handle to the registry's pool; named `mcp_pool` (not
    // `state_db_pool`) to avoid name-clash confusion with the
    // worker's deleted `state_db_pool` field. This is just the
    // controller's primary Postgres connection.
    let mcp_pool = registry.db_pool.clone();

    // Static tools ordered by priority: meta/discovery tools first so they appear
    // in any client that truncates by position. session_start, tool_search, and
    // get_platform_info must always be reachable regardless of client tool limits.
    //
    // Priority ordering:
    //   1. advanced  — session_start, restore_pinned_modules (session lifecycle)
    //   2. platform  — get_platform_info, get_platform_hygiene_report (health)
    //   3. search    — tool_search, search_workflows, search_modules (discovery)
    //   4. workflows — create_workflow, trigger_workflow, … (core ops)
    //   5. modules   — list_modules, delete_module, … (module management)
    //   6. sandbox   — compile_custom_sandbox, run_sandbox, … (compilation)
    //   7. executions — get_execution_status, list_executions, … (results)
    //   8–17: remaining domains by rough usage frequency
    let mut tools: Vec<serde_json::Value> = [
        advanced::tool_schemas(),   // positions  0–~25  — session_start FIRST
        platform::tool_schemas(),   // positions ~26–~35  — get_platform_info
        search::tool_schemas(),     // positions ~36–~47  — tool_search
        workflows::tool_schemas(),  // positions ~48–~83  — core workflow ops
        modules::tool_schemas(),    // positions ~84–~100 — module management
        sandbox::tool_schemas(),    // positions ~101–~109 — compilation
        executions::tool_schemas(), // positions ~110–~141 — execution results
        actor::tool_schemas(),      // positions ~142–~168 — actor management
        analytics::tool_schemas(),  // positions ~169–~200 — analytics
        secrets::tool_schemas(),
        schedules::tool_schemas(),
        versions::tool_schemas(),
        webhooks::tool_schemas(),
        graph::tool_schemas(),
        knowledge_graph::tool_schemas(),
        alerts::tool_schemas(),
        schemas::tool_schemas(),
        ollama::tool_schemas(),
    ]
    .concat();

    // Batch-fetch capability worlds for all templates in a single query (avoids N+1)
    let template_ids: Vec<uuid::Uuid> = templates.iter().map(|t| t.id).collect();
    let mod_repo = talos_module_repository::ModuleRepository::new(mcp_pool.clone());
    let world_rows = mod_repo
        .list_template_world_overrides(&template_ids)
        .await
        .unwrap_or_default();

    let world_map: std::collections::HashMap<uuid::Uuid, String> = world_rows.into_iter().collect();

    for t in templates {
        // Skip non-executable template categories from the direct tool list:
        // - sandbox: user-created sandboxes (available via list_modules)
        // - workflow_template: saved workflow graphs (not Rust code, can't be JIT compiled)
        if t.category == "sandbox" || t.category == "workflow_template" {
            continue;
        }

        let template_world = world_map
            .get(&t.id)
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let world_base = talos_capability_world::world_short(&template_world);
        let has_cap = agent.has_capability(world_base)
            || agent
                .allowed_capabilities
                .iter()
                .any(|c| format!("{}-node", c) == template_world);
        if !has_cap && template_world != "minimal" {
            continue;
        }

        // MCP TypeScript SDK clients (incl. Claude Code 2025+) validate every
        // tool's inputSchema with strict Zod and require `type: "object"`.
        // A SINGLE malformed schema causes the client to silently drop the
        // ENTIRE tools/list response — every tool disappears from the UI.
        // Catalog rows that persist `config_schema: {}` (empty object) or any
        // value lacking `type: "object"` triggered exactly this in the wild
        // (compute_window-v1 + persist-v1, 2026-04-23). Normalize defensively.
        let default_schema = || {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "input": {
                        "type": "string",
                        "description": "Input data for the node"
                    }
                },
                "required": ["input"]
            })
        };
        let input_schema = match t.config_schema {
            serde_json::Value::Null => default_schema(),
            serde_json::Value::Object(mut obj) => {
                if obj.get("type").and_then(|v| v.as_str()) != Some("object") {
                    obj.insert("type".to_string(), serde_json::json!("object"));
                }
                if !obj.contains_key("properties") {
                    obj.insert("properties".to_string(), serde_json::json!({}));
                }
                serde_json::Value::Object(obj)
            }
            // Non-null, non-object value (string/number/array/bool) is invalid
            // as a JSON Schema — replace with the safe default rather than
            // emit something Zod will reject.
            _ => default_schema(),
        };

        let base_desc = t.description.unwrap_or_default();
        let raw_slug = sanitize_tool_name(&t.name).to_lowercase().replace('_', "-");
        let catalog_slug = raw_slug
            .split('-')
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join("-");
        let full_desc = format!(
            "{base_desc} \
             [Catalog module: calling this tool installs it and returns a module_id \
             ready for add_node_to_workflow. Equivalent to install_module_from_catalog(name: '{}').]",
            catalog_slug
        );
        tools.push(serde_json::json!({
            "name": format!("{}-v1", sanitize_tool_name(&t.name)),
            "description": full_desc,
            "inputSchema": input_schema
        }));
    }

    // Return all tools in a single response — no pagination.
    //
    // MCP pagination is optional (servers MAY support it). The overwhelming majority
    // of MCP clients do NOT follow nextCursor, so paginating silently hides tools
    // from clients that only issue one tools/list request. Returning all tools at once
    // is both spec-compliant and universally compatible.
    //
    // Size budget: 275 static tools × ~700 bytes ≈ 193 KB — well within limits for
    // stdio, SSE, and Streamable HTTP transports.
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: req.id,
        result: Some(serde_json::json!({ "tools": tools })),
        error: None,
    }
}

async fn handle_tools_call(
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

    if let Some(r) = sandbox::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return r;
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
        return r;
    }
    if let Some(r) = executions::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await
    {
        return r;
    }
    if let Some(r) = secrets::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return r;
    }
    if let Some(r) = schedules::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return r;
    }
    if let Some(r) = versions::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return r;
    }
    if let Some(r) = webhooks::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return r;
    }
    if let Some(r) = graph::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return r;
    }
    if let Some(r) = modules::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return r;
    }
    if let Some(r) = analytics::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return r;
    }
    if let Some(r) = search::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return r;
    }
    if let Some(r) = alerts::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return r;
    }
    if let Some(r) =
        knowledge_graph::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await
    {
        return r;
    }
    if let Some(r) =
        configuration::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await
    {
        return r;
    }
    if let Some(r) = platform::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return r;
    }
    if let Some(r) = advanced::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return r;
    }
    if let Some(r) = actor::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return r;
    }
    if let Some(r) = ollama::dispatch(name, req.id.clone(), &args, &state, agent.clone()).await {
        return r;
    }

    // Dynamic catalog template tools (e.g. "Redis_Cache-v1", "HTTP_Request-v1") are in the
    // manifest but have no static dispatch handler.  When called directly, route them to
    // install_module_from_catalog so the module gets compiled and the caller receives a
    // module_id ready for add_node_to_workflow.  The "-v1" suffix is stripped and the
    // remaining sanitized name is lowercased + underscores-to-hyphens to recover the catalog slug.
    if let Some(sanitized) = name.strip_suffix("-v1") {
        // Collapse consecutive hyphens that arise from double-underscore display names
        // (e.g. "Stripe__Create_Customer" → "stripe--create-customer" → "stripe-create-customer").
        let raw = sanitized.to_lowercase().replace('_', "-");
        let slug = raw
            .split('-')
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join("-");
        let install_args = serde_json::json!({ "name": slug });
        if let Some(r) = modules::dispatch(
            "install_module_from_catalog",
            req.id.clone(),
            &install_args,
            &state,
            agent.clone(),
        )
        .await
        {
            return r;
        }
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
