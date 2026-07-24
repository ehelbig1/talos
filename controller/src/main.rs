#![allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::needless_return
)]
// async-graphql 7.x's macro expansion of MutationRoot::add_set walks the
// schema metadata at compile time and overflows the default 128-deep
// recursion limit when building the bin target. The lib target carries the
// same attribute (controller/src/lib.rs); bin and lib are separate crates
// in cargo's build model so the attribute doesn't propagate — both need
// their own. Keep these two values in sync.
#![recursion_limit = "256"]
// Per-module `#[allow(dead_code)]` is used where intentional (API surface not
// yet wired, feature-gated code). The crate-wide allow was removed to surface
// truly dead code during development.
use axum::{
    extract::{ws::WebSocketUpgrade, ConnectInfo, DefaultBodyLimit, State},
    response::Response,
    routing::{get, post},
    Extension, Router,
};
use futures::StreamExt; // For NATS subscriber
use tower_cookies::CookieManagerLayer;
// tracing imports used in other modules
// (removed redundant import; using fully qualified calls)

mod audit_ledger;
mod engine;
mod trace;
mod trace_nats;
use controller::metrics;
mod errors;
use async_graphql::Schema;
// TalosSchema canonical home is now `talos_api`. Re-exported through
// `controller::lib::TalosSchema` for back-compat.
pub use controller::TalosSchema;

use crate::db::init_pool;
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::http::{header, HeaderValue, Request};
use axum::middleware::{from_fn, Next};
use talos_worker_runtime::runtime::TalosRuntime;
use tokio::sync::broadcast;

mod actor_memory_service;
mod actor_policies;
mod actor_repository;
mod actor_scaffold_service;
mod advanced_repository;
mod analytics_repository;
mod api;
mod api_docs;
mod api_keys;
mod atlassian;
mod auth;
mod capability_downgrade;
mod compilation;
mod config;
mod cost_attribution;
mod csrf;
mod db;
mod db_monitor;
mod distributed_ratelimit;
mod dlp;
mod execution_repository;
mod gmail;
mod google_calendar;
mod google_cloud;
mod graph_rag;
mod idempotency;
mod integrations;
mod jobs;
mod llm;
mod mcp;
mod memory_crypto;
mod module_executions;
mod module_payload_encryption;
mod module_repository;
mod node_cache;
mod oauth;
mod organizations;
mod rate_limit;
mod registry;
mod replay_diff;
mod request_id;
mod retry_intelligence;
mod schedule_repository;
mod scheduler;
mod secrets;
mod security_headers;
mod shutdown;
mod slack;
mod subworkflow_contract_service;
mod system_repository;
mod templates;
mod text_util;
mod totp_2fa;
mod webhook_repository;
mod webhooks;
mod wit_inspector;
mod worker_manager;
mod workflow_authorization;
mod workflow_creation_helpers;
mod workflow_repository;
mod workflow_signing;
mod workflow_validation;
mod workflow_versions;
mod ws_auth;
mod yaml_workflows;

mod bootstrap;
mod cli;

// 2026-07 main.rs decomposition: the bootstrap-phase bodies (service
// construction, background-task spawns, route-local HTTP handlers, CLI
// subcommands) moved verbatim into bin-private modules. Re-export them at
// the crate root so `main()` / `build_router` / `serve` call sites — and
// cross-module references — keep their original bare-identifier form.
// `build_router` (every `.route(`/`.nest(` registration) lives in
// `bootstrap/router.rs`; lint check 2 (route <-> nginx ConfigMap alignment)
// greps BOTH controller/src/main.rs AND controller/src/bootstrap/router.rs for
// those registrations so the guardrail follows the routes.
pub(crate) use bootstrap::background::*;
pub(crate) use bootstrap::router::*;
pub(crate) use bootstrap::services::*;
pub(crate) use cli::*;

use api::schema::{MutationRoot, QueryRoot, SubscriptionRoot};
use auth::AuthService;
use compilation::CompilationService;
use engine::events::{ExecutionEvent, ExecutionStatus};
use module_executions::{LogLevel, ModuleExecutionService};
use oauth::{OAuthProvider, OAuthService};
use registry::ModuleRegistry;
use secrets::SecretsManager;
#[allow(clippy::single_component_path_imports)]
use talos_workflow_job_protocol;
use webhooks::WebhookRouter;

// Type alias for the full GraphQL schema: see the `TalosSchema` re-export at
// the top of this file (canonical home is `talos_api`).

// ---------------------------------------------------------------------------
// Startup decomposition (2026-07-01). `main()` was a single ~4,900-line
// sequential body; it is now a readable sequence of phase functions. The
// extraction was purely mechanical — every block moved verbatim (with its
// comments) out of `main()` into a module-level function below, and the
// phase structs group the values that used to be `let` bindings threaded
// through the body. Startup ORDER is load-bearing (crypto hooks before RPC
// subscribers, HMAC ring registration before subscriber spawn, probe routes
// merged after rate-limit layers, ...) — do not reorder the calls in
// `main()` without reading the comments in the corresponding phase function.
// ---------------------------------------------------------------------------

/// Broadcast buses created before any service construction.
struct EventBuses {
    /// Execution updates — consumed by the GraphQL schema (`.data(tx)`), the
    /// webhook router, the WASM-log subscriber, and the orchestration service.
    tx: broadcast::Sender<ExecutionEvent>,
    /// Clone taken before the schema builder consumes `tx` — needed by the scheduler.
    tx_for_scheduler: broadcast::Sender<ExecutionEvent>,
    dlq_tx: broadcast::Sender<crate::engine::events::DlqEvent>,
    workflow_execution_tx: broadcast::Sender<crate::engine::events::WorkflowExecutionEvent>,
}

/// Module registry + compiler + secrets manager — the services everything
/// else hangs off. Built first so the crypto hooks can be registered before
/// any other service touches encrypted data.
struct CoreServices {
    registry: std::sync::Arc<ModuleRegistry>,
    compiler: std::sync::Arc<CompilationService>,
    compilation_event_tx: broadcast::Sender<crate::engine::events::CompilationEvent>,
    secrets_manager: std::sync::Arc<SecretsManager>,
}

/// The integration / auth / OAuth / webhook service pile. Field order
/// mirrors the construction order in `build_platform_services` (which is the
/// pre-decomposition `main()` body order).
struct PlatformServices {
    worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey>,
    worker_manager: std::sync::Arc<crate::worker_manager::WorkerManager>,
    dlp_service: std::sync::Arc<dlp::DlpService>,
    module_execution_service: std::sync::Arc<ModuleExecutionService>,
    oauth_credential_service: std::sync::Arc<oauth::OAuthCredentialService>,
    slack_api_client: std::sync::Arc<slack::SlackApiClient>,
    slack_integration_service: std::sync::Arc<slack::SlackIntegrationService>,
    gmail_integration_service: std::sync::Arc<gmail::GmailIntegrationService>,
    google_cloud_integration_service: std::sync::Arc<google_cloud::GoogleCloudIntegrationService>,
    google_cloud_write_service: std::sync::Arc<google_cloud::GoogleCloudIntegrationService>,
    google_cloud_full_service: std::sync::Arc<google_cloud::GoogleCloudIntegrationService>,
    github_connect_service: std::sync::Arc<talos_github_connect::GithubConnectService>,
    gmail_watch_service: Option<std::sync::Arc<gmail::watch::GmailWatchService>>,
    gmail_pubsub_verifier: Option<std::sync::Arc<gmail::pubsub_jwt::PubsubJwtVerifier>>,
    // Google Cloud (Cloud Monitoring) push — all None unless
    // GCP_PUBSUB_AUDIENCE is set. The verifier is the SHARED
    // GoogleOidcVerifier (audience passed per-call), so the operator
    // audience is stored separately for the push handler state.
    gcp_watch_service: Option<std::sync::Arc<google_cloud::watch::GcpWatchService>>,
    gcp_pubsub_verifier:
        Option<std::sync::Arc<talos_integration_helpers::google_jwt::GoogleOidcVerifier>>,
    gcp_pubsub_audience: Option<String>,
    atlassian_integration_service: std::sync::Arc<atlassian::AtlassianIntegrationService>,
    gmail_api_client: std::sync::Arc<gmail::GmailApiClient>,
    google_calendar_service: std::sync::Arc<google_calendar::GoogleCalendarService>,
    circuit_breaker: std::sync::Arc<crate::webhooks::CircuitBreaker>,
    webhook_router: std::sync::Arc<WebhookRouter>,
    auth_service: std::sync::Arc<AuthService>,
    totp_service: std::sync::Arc<totp_2fa::TotpService>,
    api_key_service: std::sync::Arc<api_keys::ApiKeyService>,
    oauth_service: std::sync::Arc<OAuthService>,
    auth_rate_limiter: std::sync::Arc<rate_limit::DistributedRateLimiter>,
    idempotency_service: Option<std::sync::Arc<idempotency::IdempotencyService>>,
}

/// Per-IP / global rate limiters + proxy trust config shared between the
/// cleanup sweeps, the router layers, and the startup banner.
struct RateLimiters {
    api_rate_limit: u32,
    webhook_rate_limit: u32,
    global_rate_limit: u32,
    api_limiter: rate_limit::IpRateLimiter,
    webhook_limiter: rate_limit::IpRateLimiter,
    global_limiter: rate_limit::GlobalRateLimiter,
    whitelist: std::sync::Arc<rate_limit::IpWhitelist>,
    trusted_proxies: std::sync::Arc<rate_limit::TrustedProxies>,
}

/// GraphQL schema + the cross-protocol services / repositories shared
/// between the GraphQL ctx.data wiring and the MCP router.
struct SchemaBundle {
    schema: TalosSchema,
    runtime: std::sync::Arc<TalosRuntime>,
    llm_client: Option<std::sync::Arc<crate::llm::LlmClient>>,
    workflow_repo: std::sync::Arc<workflow_repository::WorkflowRepository>,
    module_repo: std::sync::Arc<module_repository::ModuleRepository>,
    execution_repo: std::sync::Arc<crate::execution_repository::ExecutionRepository>,
    workflow_creation_service: std::sync::Arc<talos_workflow_creation::WorkflowCreationService>,
    hot_update_service: std::sync::Arc<talos_hot_update_service::HotUpdateService>,
    execution_orchestration_service:
        std::sync::Arc<talos_execution_orchestration::ExecutionOrchestrationService>,
    workflow_manifest_service: std::sync::Arc<talos_workflow_manifest::WorkflowManifestService>,
    replay_service: std::sync::Arc<talos_replay_service::ReplayService>,
    inline_compile_service: std::sync::Arc<talos_inline_compile_service::InlineCompileService>,
    search_service: std::sync::Arc<talos_search_service::SearchService>,
    failure_analysis_service:
        std::sync::Arc<talos_failure_analysis_service::FailureAnalysisService>,
    actor_lifecycle_service: std::sync::Arc<talos_actor_lifecycle_service::ActorLifecycleService>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls 0.23 requires a process-level CryptoProvider. We have multiple
    // crates pulling rustls in (redis tls-rustls, sqlx-postgres rustls
    // backend, reqwest rustls TLS), and rustls won't auto-pick when more
    // than one provider is in the dep graph. Install the ring provider
    // explicitly. Idempotent — install_default returns Err if one is
    // already installed; we ignore that to stay tolerant of test setups.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Subcommand dispatch — ALWAYS the very first thing in main() so build /
    // CI flows that need the controller binary as a tool (not a server) don't
    // pay the cost of full server initialisation. Subcommands run to
    // completion and exit; the server path takes over only when no
    // subcommand matched.
    let args: Vec<String> = std::env::args().collect();
    if let Some(sub) = args.get(1) {
        match sub.as_str() {
            "publish-templates" => return run_publish_templates_cli(&args[2..]).await,
            "generate-worker-trust-keypair" => {
                return run_generate_worker_trust_keypair_cli(&args[2..]);
            }
            "register-worker-identity"
            | "list-worker-identities"
            | "deactivate-worker-identity" => {
                return run_worker_identity_cli(sub, &args[2..]).await;
            }
            "mint-worker-provisioning-token"
            | "list-worker-provisioning-tokens"
            | "revoke-worker-provisioning-token" => {
                return run_worker_provisioning_token_cli(sub, &args[2..]).await;
            }
            "--help" | "-h" => {
                println!("Usage:");
                println!("  controller                            Run the HTTP server (default)");
                println!(
                    "  controller publish-templates [opts]   Compile bundled templates to WASM"
                );
                println!(
                    "                                        and emit a registry-ready bundle"
                );
                println!("                                        for `oras push`. See");
                println!("                                        .github/workflows/template-publish.yml");
                println!("  controller generate-worker-trust-keypair --role <controller|worker>");
                println!(
                    "                                        [--worker-id <id>]  Mint an Ed25519"
                );
                println!(
                    "                                        keypair for the RFC 0010 worker-trust"
                );
                println!(
                    "                                        boundary and print the env block."
                );
                println!(
                    "  controller register-worker-identity --worker-id <id> --public-key <hex>"
                );
                println!(
                    "                                        [--supports-sealing]  Operator-register"
                );
                println!(
                    "                                        a worker's Ed25519 key in the DB registry."
                );
                println!(
                    "  controller list-worker-identities     List the DB worker-identity registry."
                );
                println!(
                    "  controller deactivate-worker-identity --worker-id <id> --public-key <hex>"
                );
                println!(
                    "                                        Soft-retire one registered key (rotation)."
                );
                println!(
                    "  controller mint-worker-provisioning-token --worker-id <id> | --wildcard"
                );
                println!(
                    "                                        [--ttl-hours <n>] [--note <text>]"
                );
                println!(
                    "                                        Mint a single-use registration token"
                );
                println!(
                    "                                        (RFC 0010 P2; bound tokens authorize"
                );
                println!("                                        exactly one worker_id).");
                println!(
                    "  controller list-worker-provisioning-tokens   List minted tokens (no secrets)."
                );
                println!("  controller revoke-worker-provisioning-token --id <uuid>");
                println!("                                        Revoke an un-redeemed token.");
                return Ok(());
            }
            // Anything else: fall through to server mode (preserves existing
            // behaviour where the binary ignores unknown args).
            _ => {}
        }
    }

    let _ = dotenvy::dotenv();

    // SECURITY: Guard against the dev CSRF bypass being accidentally enabled in production.
    // The bypass variable is ALLOW_DEV_UNSAFE_CSRF_BYPASS (same name used by csrf.rs).
    // MCP-1066 (2026-05-15): route through `talos_config::dev_csrf_bypass_enabled()`
    // so this fail-closed startup panic catches every canonical truthy token
    // (true | 1 | yes | on). Pre-fix the case-sensitive `== "true"` predicate
    // would NOT panic on `=1`/`=yes`/`=TRUE`, but the request-time CSRF gate
    // in talos-csrf used the same case-sensitive predicate so they agreed by
    // chance. Both sites now share the canonical resolver — any future
    // bypass-consuming site that uses `bool_env_or_default` can't diverge.
    if config::is_production() && talos_config::dev_csrf_bypass_enabled() {
        panic!("CRITICAL SECURITY ERROR: ALLOW_DEV_UNSAFE_CSRF_BYPASS cannot be enabled in production mode!");
    }

    // Initialise the logger + tracing subscriber (OTLP bridge when configured).
    init_tracing_and_logging();

    // Verify essential environment configuration early (fail-fast gate).
    validate_startup_config()?;

    // Public base-URL discovery (ngrok sidecar, compose `public`
    // profile). No-op when TALOS_NGROK_API_URL is unset; otherwise a
    // background poll keeps externally-reachable endpoint formatting
    // (Pub/Sub push, watch webhooks, inbound webhooks, approval links)
    // pointed at the live tunnel origin. See talos-public-url.
    talos_public_url::spawn_discovery();

    // Event buses for execution / DLQ / workflow-started updates.
    let buses = build_event_buses();

    // Postgres pool + migrations + first-user bootstrap + embedding warmup.
    let db_pool: sqlx::Pool<sqlx::Postgres> = init_database().await?;

    // Redis (distributed caching) and NATS (job dispatch + RPC) clients.
    let redis_client = init_redis().await;
    let nats_client = init_nats().await?;

    // Module registry, compiler, and the secrets manager (KEK provider selection).
    let core = build_core_services(db_pool.clone(), redis_client.clone()).await?;

    // At-rest crypto hooks + the audit-ledger subscriber. MUST run before any
    // memory writes and before the RPC subscribers start (hook-before-
    // subscriber ordering is load-bearing — writers panic-loud without it).
    register_crypto_hooks(
        db_pool.clone(),
        nats_client.clone(),
        core.secrets_manager.clone(),
    )
    .await?;

    // Integration / auth / OAuth / webhook service pile (+ metrics service
    // and the embedding-provider boot probe, in original construction order).
    let services = build_platform_services(
        db_pool.clone(),
        redis_client.clone(),
        nats_client.clone(),
        &buses,
        &core,
    )
    .await?;

    // Embedding re-probe + crypto-invariant orphan gauges + DB-pool gauges.
    spawn_metrics_gauge_tasks(db_pool.clone());

    // Seed templates on first run
    seed_templates(&core.registry, core.compiler.clone()).await?;
    seed_marketplace(&db_pool).await;

    // OCI registry background sync loop (started after disk seeding).
    spawn_registry_sync(core.registry.clone());

    // ---------- Background-sweep shutdown channel ----------
    //
    // Long-running tick-driven sweeps (LLM-keys, actor-memory TTL, scheduler)
    // need a fan-out shutdown signal so they can drain in-flight work on
    // SIGTERM instead of being abruptly aborted with the runtime. Use a
    // tokio::sync::watch — single-producer, multi-consumer, .changed()
    // future yields when the value flips. Notified once from the
    // axum::serve graceful-shutdown callback at the bottom of main().
    //
    // Distinct from `rpc_shutdown_tx` (declared further down with the
    // RPC subscribers); both fire on the same trigger but their lifecycles
    // start at different points in startup, so they're separate channels.
    let (bg_shutdown_tx, bg_shutdown_rx) = tokio::sync::watch::channel::<bool>(false);
    let bg_shutdown_tx = std::sync::Arc::new(bg_shutdown_tx);

    // LLM-keys/DEK cache sweeps, audit-chain verification, bcrypt-cache
    // revocation, and modules-table reconciliation loops.
    spawn_maintenance_sweeps(
        db_pool.clone(),
        core.secrets_manager.clone(),
        bg_shutdown_rx.clone(),
    );

    // Per-IP / global rate limiters + IP whitelist + trusted proxies.
    let limiters = build_rate_limiters();

    // Session/API-key/OAuth-state/execution/audit-log/WASM-cache/rate-limiter
    // cleanup sweeps, plus the one-shot crash-recovery resume sweep (RFC 0003).
    spawn_cleanup_tasks(
        db_pool.clone(),
        nats_client.clone(),
        &core,
        &services,
        &limiters,
        bg_shutdown_rx.clone(),
    );

    // Build `actor_repo` here (earlier than the rest of the service
    // pile below) so the Graph RAG init block can hand it in for
    // tier-1 enforcement. It's independent of the services that
    // come between this point and its second use site at the bulk
    // service-construction block, so the early build is free.
    let actor_repo = std::sync::Arc::new(
        actor_repository::ActorRepository::new(db_pool.clone())
            .with_encryption(core.secrets_manager.clone()),
    );

    // Graph RAG (Neo4j) init — TLS prod gate + tier-1 egress gate wiring.
    init_graph_rag(core.secrets_manager.clone(), actor_repo.clone()).await?;

    // HMAC verify-ring registration MUST precede the RPC subscriber spawns,
    // otherwise verify() fails closed and every request returns Unauthorized.
    let rpc_subscribers_enabled = register_rpc_hmac_ring()?;
    // Distributed replay-nonce guard (codebase-review finding #2). Opt-in via
    // TALOS_DISTRIBUTED_REPLAY: when enabled AND Redis is configured, register a
    // Redis-backed shared guard so a signed RPC replayed to a DIFFERENT
    // controller replica within the freshness window is rejected fleet-wide (the
    // per-replica nonce cache can't see cross-replica replays). Default OFF → no
    // guard registered → subscriber behaviour identical to before. Registered
    // before the subscribers spawn so no request races an unregistered guard.
    register_distributed_replay_guard(redis_client.as_ref()).await;
    let rpc_shutdown_tx = wire_rpc_subscribers(
        db_pool.clone(),
        nats_client.clone(),
        rpc_subscribers_enabled,
        core.secrets_manager.clone(),
    );

    // RFC 0011 P2d: install the DISTILL hook context (the engine's
    // node hook consumes `__ml_distill__` envelopes through it) and
    // start the bounded lifecycle policy evaluator. Installed BEFORE
    // any workflow can run so no envelope races an unset OnceLock (an
    // unset context drops envelopes with a WARN, never panics).
    let _ = talos_ml::DISTILL_CONTEXT.set(talos_ml::DistillContext {
        db_pool: db_pool.clone(),
        dataset_service: talos_ml::DatasetService::new(core.secrets_manager.clone()),
        lifecycle_service: talos_ml::LifecycleService::new(core.secrets_manager.clone()),
    });

    // R2 token ledger: install the two process-wide LLM usage recorders
    // (same OnceLock boot-wiring pattern as DISTILL_CONTEXT above), before
    // any workflow can run.
    //
    // 1. Engine-dispatch sink — every NatsNodeDispatcher built by
    //    `build_nats_dispatcher` records verified worker-result usage here.
    //    Identity arrives from the CONTROLLER-side dispatch context and is
    //    re-resolved against `workflow_executions` inside
    //    `record_llm_usage` — never from worker claims.
    {
        let usage_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
        talos_engine::nats_run::install_llm_usage_sink(std::sync::Arc::new(
            move |report: talos_workflow_engine_nats::LlmUsageReport| {
                let repo = usage_repo.clone();
                let entries: Vec<talos_actor_repository::LlmUsageInsert> = report
                    .entries
                    .iter()
                    .map(|u| talos_actor_repository::LlmUsageInsert {
                        provider: u.provider.clone(),
                        model: u.model.clone(),
                        prompt_tokens: i64::from(u.prompt_tokens),
                        completion_tokens: i64::from(u.completion_tokens),
                        calls: i32::try_from(u.calls).unwrap_or(i32::MAX),
                    })
                    .collect();
                // Spawned + best-effort: accounting must never block or fail
                // the dispatch hot path.
                tokio::spawn(async move {
                    if let Err(e) = repo
                        .record_llm_usage(
                            Some(report.execution_id),
                            report.actor_id,
                            report.user_id,
                            &entries,
                        )
                        .await
                    {
                        tracing::warn!(
                            execution_id = %report.execution_id,
                            error = %e,
                            "failed to record worker LLM usage"
                        );
                    }
                });
            },
        ));
    }
    // 2. Controller-side client sink — talos-llm's generate_code /
    //    generate_text / scaffold_workflow / OllamaClient::complete record
    //    here. user_id arrives via the `talos_llm::usage::scoped_user`
    //    task-local when the call site knows the requesting user; NULL
    //    user/actor rows are platform-attributed (documented in the
    //    llm_usage migration).
    {
        let usage_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
        talos_llm::usage::set_usage_sink(std::sync::Arc::new(
            move |rec: talos_llm::usage::LlmUsageRecord| {
                let repo = usage_repo.clone();
                let entry = talos_actor_repository::LlmUsageInsert {
                    provider: rec.provider,
                    model: rec.model,
                    prompt_tokens: i64::try_from(rec.prompt_tokens).unwrap_or(i64::MAX),
                    completion_tokens: i64::try_from(rec.completion_tokens).unwrap_or(i64::MAX),
                    calls: 1,
                };
                let user_id = rec.user_id;
                tokio::spawn(async move {
                    if let Err(e) = repo.record_llm_usage(None, None, user_id, &[entry]).await {
                        tracing::warn!(error = %e, "failed to record controller LLM usage");
                    }
                });
            },
        ));
    }
    // Shared local-LLM (Ollama) transport — ONE process-wide instance,
    // reused by BOTH the MCP teacher-audit handler (threaded into McpState
    // via build_router → create_router) AND the automatic teacher-audit
    // scheduler below, so they share one reqwest connection pool. MCP-630
    // idiom: a Helm placeholder `OLLAMA_URL=""` falls through to the
    // in-cluster default rather than producing a base-URL-less client.
    let ollama_client = std::sync::Arc::new(talos_llm::OllamaClient::new(talos_config::get_env(
        "OLLAMA_URL",
        "http://ollama:11434",
    )));

    // B1: probe the local Ollama backend ONCE at boot for the autonomous memory
    // loops. Those loops route LOCAL-FIRST (external is a budget-gated fallback),
    // so the `ollama_available` signal they consult MUST reflect REAL
    // reachability — not merely that a client object exists (it always does; the
    // `OllamaClient` is constructed unconditionally with an in-cluster default
    // URL). Without this probe, a fresh production deploy with Ollama disabled
    // (`ollama.enabled: false`) would route every tier-2 actor to a dead local
    // endpoint every tick — permanent per-actor WARN spam, memory never
    // consolidates, and the external fallback the docs promise never fires. A
    // `None` here disables local summarization for the memory loops: tier-2
    // actors go straight to the external provider (budget-gated), tier-1 actors
    // Skip (they can't egress). The runtime tier-2 failure-fallback still covers
    // a backend that goes down AFTER a successful boot probe. Bounded 3s timeout
    // so a down backend can't stall startup. Scoped to the memory loops only —
    // teacher-audit / graph-RAG keep the raw client and handle their own errors.
    let memory_loop_ollama = match tokio::time::timeout(
        std::time::Duration::from_secs(3),
        ollama_client.list_models(),
    )
    .await
    {
        Ok(Ok(_)) => {
            tracing::info!(
                target: "talos_memory",
                "Ollama reachable at boot — memory loops summarize LOCAL-FIRST"
            );
            Some(ollama_client.clone())
        }
        Ok(Err(e)) => {
            tracing::warn!(
                target: "talos_memory",
                error = %e,
                "Ollama unreachable at boot — memory loops route tier-2 to the external fallback; tier-1 actors Skip"
            );
            None
        }
        Err(_) => {
            tracing::warn!(
                target: "talos_memory",
                "Ollama boot probe timed out — memory loops route tier-2 to the external fallback; tier-1 actors Skip"
            );
            None
        }
    };
    talos_ml::spawn_policy_evaluator(
        db_pool.clone(),
        talos_ml::DatasetService::new(core.secrets_manager.clone()),
        std::sync::Arc::new(talos_ml::LifecycleService::new(
            core.secrets_manager.clone(),
        )),
        bg_shutdown_rx.clone(),
    );
    // RFC 0011 P2d: disagreement-digest delivery — surfaces pending
    // fast-vs-LLM divergences to each model's configured digest actor so
    // the human-in-the-loop corrections the promotion policy requires
    // actually get made.
    talos_ml::spawn_disagreement_digest(
        db_pool.clone(),
        std::sync::Arc::new(talos_ml::LifecycleService::new(
            core.secrets_manager.clone(),
        )),
        bg_shutdown_rx.clone(),
    );
    // RFC 0011 R3: automatic weekly teacher-vs-gold audits — every
    // correction-bearing model gets a fresh bare-prompt ceiling stamped on
    // its card (TALOS_TEACHER_AUDIT_INTERVAL_DAYS cadence) so the weekly
    // assistant report can always cite one, without a human running
    // ml_teacher_audit by hand. Reuses the shared Ollama transport above.
    talos_ml::spawn_teacher_audit_scheduler(
        db_pool.clone(),
        talos_ml::DatasetService::new(core.secrets_manager.clone()),
        Some(ollama_client.clone()),
        bg_shutdown_rx.clone(),
    );

    // Phase 3b: autonomous actor-memory consolidation. Default-ON (Tier 3,
    // ENABLE_MEMORY_CONSOLIDATION) — spawn_* returns without a task when
    // disabled. LOCAL-FIRST: summarizes on the on-host Ollama for all tiers when
    // reachable (external is a budget-gated fallback); tier-1 actors only
    // consolidate on Ollama when attested, else Skip (shared tier gate).
    talos_memory_consolidation::spawn_memory_consolidation_scheduler(
        db_pool.clone(),
        talos_actor_repository::ActorRepository::new(db_pool.clone()),
        memory_loop_ollama.clone(),
        core.secrets_manager.clone(),
        bg_shutdown_rx.clone(),
    );

    // Phase 3: autonomous actor-memory REFLECTION. Default-ON (Tier 3,
    // ENABLE_MEMORY_REFLECTION) — spawn_* returns without a task when disabled.
    // Reads across an actor's meaningful memories and synthesizes higher-order
    // insights LOCAL-FIRST (on-host Ollama for all tiers when reachable; external
    // is a budget-gated fallback; tier-1 → local only when attested, else Skip),
    // writing ONE non-destructive `reflection`-kind semantic memory. Distinct
    // rotation cursor (last_reflected_at) from consolidation.
    talos_memory_consolidation::spawn_memory_reflection_scheduler(
        db_pool.clone(),
        talos_actor_repository::ActorRepository::new(db_pool.clone()),
        memory_loop_ollama.clone(),
        core.secrets_manager.clone(),
        bg_shutdown_rx.clone(),
    );

    // Adaptive per-actor memory ranking — Phase 2 (learned ranker). Default-ON
    // (Tier 3, ENABLE_ADAPTIVE_RANK_TRAINING) — spawn_* returns without a task
    // when disabled. Pure numeric fit over the Phase-1 provenance corpus: no LLM,
    // no secrets, no tier gate (zero data egress). Cold-start fail-closed to
    // global weights until an actor has enough labeled examples.
    talos_memory_ranking::spawn_rank_training_scheduler(
        db_pool.clone(),
        talos_actor_repository::ActorRepository::new(db_pool.clone()),
        bg_shutdown_rx.clone(),
    );

    // Embedding backfill, readiness recomputation, SLA degradation alerting.
    spawn_analytics_tasks(db_pool.clone(), bg_shutdown_rx.clone());

    // Gmail watch / Google Calendar channel renewal + OAuth token refresh.
    spawn_integration_renewal_tasks(&services, bg_shutdown_rx.clone());

    // WASM-log + job-result NATS subscribers (supervisor-wrapped).
    spawn_nats_log_subscribers(db_pool.clone(), nats_client.clone(), &services, &buses)?;

    // GraphQL schema + the cross-protocol services shared with MCP.
    let bundle = build_schema_and_services(
        db_pool.clone(),
        redis_client.clone(),
        nats_client.clone(),
        &buses,
        &core,
        &services,
        actor_repo.clone(),
    )?;

    // Axum router — route/middleware/Extension assembly. Middleware ORDER and
    // sub-router merge ORDER are load-bearing; see build_router's comments.
    let app = build_router(
        db_pool.clone(),
        redis_client.clone(),
        nats_client.clone(),
        &core,
        &services,
        &limiters,
        &bundle,
        actor_repo.clone(),
        ollama_client.clone(),
    )?;

    // Stale-execution cleanup, workflow scheduler, SLA threshold breach check.
    spawn_late_background_tasks(
        db_pool.clone(),
        nats_client.clone(),
        &core,
        &services,
        buses.tx_for_scheduler.clone(),
        bg_shutdown_rx.clone(),
    );

    // Bind + serve with graceful shutdown (SIGTERM/SIGINT → DLQ flush →
    // RPC-subscriber + background-sweep shutdown broadcasts).
    serve(
        app,
        &limiters,
        services.webhook_router.clone(),
        rpc_shutdown_tx,
        bg_shutdown_tx,
    )
    .await?;

    crate::trace::shutdown_tracing();
    Ok(())
}

/// Install the fmt/OTLP tracing subscriber. Extracted verbatim from the top
/// of the pre-decomposition `main()`.
fn init_tracing_and_logging() {
    // Initialise logger
    let jaeger_endpoint = std::env::var("JAEGER_ENDPOINT")
        .ok()
        .or_else(|| Some("http://localhost:4317".to_string()));

    if let Some(endpoint) = jaeger_endpoint.as_ref() {
        match crate::trace::init_tracing("talos-controller", Some(endpoint)) {
            Ok(_) => println!("      Tracing initialized (endpoint: {})", endpoint),
            Err(e) => {
                eprintln!("Warning: Failed to initialize tracing: {}", e);
                eprintln!("    Continuing without tracing...");
            }
        }
    }

    // Install the log/trace subscriber. The `fmt` layer preserves the previous
    // console output (RUST_LOG via EnvFilter, default `info`). The optional
    // OpenTelemetry bridge layer converts controller `tracing` spans into OTLP
    // spans AND — crucially — makes `tracing::Span::current().context()` carry a
    // real otel SpanContext, which is what `inject_trace_context` propagates into
    // worker job NATS headers. The bridge is present only when `init_tracing`
    // installed an SDK provider (OTLP endpoint configured); otherwise this is a
    // plain fmt subscriber, identical to before.
    {
        use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let otel_layer = crate::trace::sdk_tracer("talos-controller")
            .map(|tracer| tracing_opentelemetry::layer().with_tracer(tracer));
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer())
            .with(otel_layer)
            .init();
    }
}

/// Startup configuration validation gate (MCP-906) + process start-time
/// stamp. Extracted verbatim from `main()`.
fn validate_startup_config() -> anyhow::Result<()> {
    // ---------------------------------------------------------------------
    // Verify essential environment configuration early.
    // ---------------------------------------------------------------------
    // MCP-906 (2026-05-14): comprehensive startup configuration
    // validation via `talos_config_validator::ConfigValidator`. Pre-fix
    // this block checked only JWT_SECRET + TALOS_MASTER_KEY presence
    // and ignored the entire ConfigValidator crate, which had been
    // built (and recently maintained — MCP-597/598/599/624/522/507)
    // but never wired in. Operators with misconfigured BCRYPT_COST,
    // weak JWT_SECRET, malformed TALOS_MASTER_KEY hex, postgres://
    // scheme drift, localhost-in-production, RS256/ES256 missing
    // private/public keys, etc. only learned via cryptic downstream
    // errors. Now: one consolidated startup gate, multiple errors
    // reported in a single message, fail-fast with the canonical
    // generation commands shown inline.
    //
    // The validator handles the Docker-secrets `<VAR>_FILE` precedence
    // for JWT_SECRET via the same `read_env_or_file` semantics the
    // legacy check used (MCP-597 sibling rule).
    if let Err(e) = talos_config_validator::ConfigValidator::validate() {
        return Err(anyhow::anyhow!(e.to_string()));
    }

    // Force-initialize the process start-time stamp *before* any request handlers
    // run. PROCESS_START_TIME is a LazyLock<Instant> that records its value on
    // first access; if the first access happens inside get_platform_info the
    // elapsed time will always be ~0. Touching it here ensures the clock starts
    // ticking from server startup.
    let _ = *crate::mcp::PROCESS_START_TIME;

    Ok(())
}

/// Create the broadcast event buses. Extracted verbatim from `main()`.
fn build_event_buses() -> EventBuses {
    // ---------- Event bus for execution updates ----------
    let (tx, _rx) = broadcast::channel::<ExecutionEvent>(100);
    // Clone before the schema builder consumes tx — needed by the scheduler.
    let tx_for_scheduler = tx.clone();

    // ---------- Event bus for DLQ updates ----------
    let (dlq_tx, _dlq_rx) = broadcast::channel::<crate::engine::events::DlqEvent>(100);

    // ---------- Event bus for Workflow Started updates ----------
    let (workflow_execution_tx, _workflow_execution_rx) =
        broadcast::channel::<crate::engine::events::WorkflowExecutionEvent>(4096);

    EventBuses {
        tx,
        tx_for_scheduler,
        dlq_tx,
        workflow_execution_tx,
    }
}

/// Bind the listener and serve with graceful shutdown (SIGTERM/SIGINT →
/// DLQ flush → RPC-subscriber + background-sweep shutdown broadcasts).
/// Extracted verbatim from `main()`.
async fn serve(
    app: Router,
    limiters: &RateLimiters,
    webhook_router: std::sync::Arc<WebhookRouter>,
    rpc_shutdown_tx: std::sync::Arc<tokio::sync::watch::Sender<bool>>,
    bg_shutdown_tx: std::sync::Arc<tokio::sync::watch::Sender<bool>>,
) -> anyhow::Result<()> {
    let api_rate_limit = limiters.api_rate_limit;
    let webhook_rate_limit = limiters.webhook_rate_limit;
    let global_rate_limit = limiters.global_rate_limit;
    let addr: std::net::SocketAddr = "0.0.0.0:8000"
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid listen address"))?;
    println!("Talos Controller listening on http://{}", addr);
    println!("Rate limiting enabled:");
    println!(
        "  - API: {} requests/min per IP (burst: {})",
        api_rate_limit,
        (api_rate_limit / 5).max(10)
    );
    println!(
        "  - Webhooks: {} requests/min per IP (burst: {})",
        webhook_rate_limit,
        (webhook_rate_limit / 6).max(5)
    );
    println!(
        "  - Global: {} requests/min total (burst: {})",
        global_rate_limit,
        (global_rate_limit / 10).max(50)
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Use into_make_service_with_connect_info to provide IP addresses to rate limiter
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown({
        let rpc_shutdown_tx = rpc_shutdown_tx.clone();
        let bg_shutdown_tx = bg_shutdown_tx.clone();
        let webhook_router_shutdown = webhook_router.clone();
        async move {
            // MCP-667 (2026-05-13): route through `talos_shutdown::wait_for_shutdown`
            // so we listen for BOTH SIGTERM and SIGINT. Pre-fix the axum
            // hook only awaited `tokio::signal::ctrl_c()`, which on Unix
            // catches SIGINT only. In K8s, kubelet sends SIGTERM during
            // pod termination — the controller never observed it and ran
            // to the full `terminationGracePeriodSeconds` (30s default)
            // before getting SIGKILLed mid-request. HTTP connections
            // dropped, RPC subscribers killed mid-handler, DLQ messages
            // in-flight. The shared helper has its own MCP-501 history
            // around install-failure handling — reuse it instead of
            // re-implementing both branches here.
            talos_shutdown::wait_for_shutdown().await;
            // MCP-1131 (2026-05-16): signal the DLQ batch processor
            // to flush before tokio aborts it. Closes the explicit
            // "DLQ messages in-flight" concern in the MCP-667
            // comment above. Fired BEFORE the bg/rpc broadcasts so
            // the flush has a chance to complete while DB and NATS
            // are still up. The processor breaks out of its loop
            // immediately on `notified()` so we don't sleep here.
            webhook_router_shutdown.shutdown_dlq();
            // Broadcast to the RPC subscribers so they stop taking new
            // work; in-flight spawned handlers finish naturally. Ignore
            // the result — if the channel's closed the subscribers are
            // already gone.
            let _ = rpc_shutdown_tx.send(true);
            // Same broadcast for background-sweep tasks (LLM-keys cache,
            // actor-memory TTL). They poll on intervals and would
            // otherwise be aborted mid-tick when the runtime stops.
            let _ = bg_shutdown_tx.send(true);
        }
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to start Axum server: {}", e))?;

    Ok(())
}

// RPC subscriber bodies moved to `rpc_subscribers` 2026-04-14 to
// keep main.rs under a manageable size. All four subscribers +
// the record_rpc_metric helper live there now.
mod integration_state_service;
mod rpc_subscribers;

// build test 1773350690

mod secrets_rotation;
mod tenancy;
