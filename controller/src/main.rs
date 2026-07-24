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
mod circuit_breaker;
mod compilation;
mod config;
mod cost_attribution;
mod csrf;
mod db;
mod db_monitor;
mod distributed_ratelimit;
mod dlp;
mod execution_repository;
mod feature_flags;
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
// `build_router` itself deliberately stays in this file: lint check 2
// (route <-> nginx ConfigMap alignment) greps controller/src/main.rs for
// `.route(`/`.nest(` registrations.
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

/// Route / middleware / Extension assembly for the whole HTTP surface.
/// Extracted verbatim from `main()`. CRITICAL ordering invariants preserved
/// byte-for-byte (see the inline comments): layers run bottom-up; the
/// governor + global rate-limit layers are production-only; `mcp_router` and
/// `probe_routes` are merged AFTER the rate-limit layers so MCP traffic and
/// kubelet probes can never be 429'd; merged sub-routers re-attach the
/// Extension layers their handlers need.
fn build_router(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    redis_client: Option<std::sync::Arc<redis::Client>>,
    nats_client: Option<std::sync::Arc<async_nats::Client>>,
    core: &CoreServices,
    services: &PlatformServices,
    limiters: &RateLimiters,
    bundle: &SchemaBundle,
    actor_repo: std::sync::Arc<actor_repository::ActorRepository>,
    ollama_client: std::sync::Arc<talos_llm::OllamaClient>,
) -> anyhow::Result<Router> {
    let secrets_manager = core.secrets_manager.clone();
    let registry = core.registry.clone();
    let compiler = core.compiler.clone();
    let worker_shared_key = services.worker_shared_key.clone();
    let worker_manager = services.worker_manager.clone();
    let dlp_service = services.dlp_service.clone();
    let module_execution_service = services.module_execution_service.clone();
    let slack_api_client = services.slack_api_client.clone();
    let slack_integration_service = services.slack_integration_service.clone();
    let gmail_integration_service = services.gmail_integration_service.clone();
    let google_cloud_integration_service = services.google_cloud_integration_service.clone();
    let google_cloud_write_service = services.google_cloud_write_service.clone();
    let google_cloud_full_service = services.google_cloud_full_service.clone();
    let github_connect_service = services.github_connect_service.clone();
    let gmail_watch_service = services.gmail_watch_service.clone();
    let gmail_pubsub_verifier = services.gmail_pubsub_verifier.clone();
    let gcp_watch_service = services.gcp_watch_service.clone();
    let gcp_pubsub_verifier = services.gcp_pubsub_verifier.clone();
    let gcp_pubsub_audience = services.gcp_pubsub_audience.clone();
    let atlassian_integration_service = services.atlassian_integration_service.clone();
    let gmail_api_client = services.gmail_api_client.clone();
    let google_calendar_service = services.google_calendar_service.clone();
    let circuit_breaker = services.circuit_breaker.clone();
    let webhook_router = services.webhook_router.clone();
    let auth_service = services.auth_service.clone();
    let oauth_service = services.oauth_service.clone();
    let idempotency_service = services.idempotency_service.clone();
    let api_limiter = limiters.api_limiter.clone();
    let webhook_limiter = limiters.webhook_limiter.clone();
    let global_limiter = limiters.global_limiter.clone();
    let whitelist = limiters.whitelist.clone();
    let trusted_proxies = limiters.trusted_proxies.clone();
    let schema = bundle.schema.clone();
    let runtime = bundle.runtime.clone();
    let llm_client = bundle.llm_client.clone();
    let workflow_repo = bundle.workflow_repo.clone();
    let module_repo = bundle.module_repo.clone();
    let execution_repo = bundle.execution_repo.clone();
    let workflow_creation_service = bundle.workflow_creation_service.clone();
    let hot_update_service = bundle.hot_update_service.clone();
    let execution_orchestration_service = bundle.execution_orchestration_service.clone();
    let workflow_manifest_service = bundle.workflow_manifest_service.clone();
    let replay_service = bundle.replay_service.clone();
    let inline_compile_service = bundle.inline_compile_service.clone();
    let search_service = bundle.search_service.clone();
    // RFC 0010 P3 (M4): the SAME process-wide claim-based-sealing handle main
    // resolved for the webhook router. `shared_envelope_sealing_handle` is
    // memoized in a `OnceLock`, so this returns the identical `InFlightSeals` +
    // claim subject the claim responder subscribes to (never a second store),
    // for the Gmail-push + Google-Calendar-push fire-and-forget dispatch paths.
    let module_sealing_handle: Option<talos_integration_helpers::ModuleSealingHandle> = nats_client
        .as_ref()
        .and_then(talos_engine::nats_run::shared_envelope_sealing_handle);
    let failure_analysis_service = bundle.failure_analysis_service.clone();
    let actor_lifecycle_service = bundle.actor_lifecycle_service.clone();
    // ---------- Rate limiting configuration ----------
    // Global rate limit configuration using tower_governor
    // Recommended: 10 requests per second per IP to prevent brute-force attacks
    let governor_conf = std::sync::Arc::new(
        tower_governor::governor::GovernorConfigBuilder::default()
            .per_second(10)
            .burst_size(20)
            .finish()
            .ok_or_else(|| anyhow::anyhow!("Failed to build rate limiter"))?,
    );
    let governor_layer = tower_governor::GovernorLayer::new(governor_conf);

    // Simple handler for CORS preflight (OPTIONS) requests.
    // MCP-1172 (2026-05-17): per-request Origin echo against the
    // talos_config::is_allowed_origin allowlist — sibling fix to
    // MCP-1168 which closed the same bug on `cors_middleware`. This
    // handler is dead code in any deployment that has
    // `cors_middleware` layered (the middleware's OPTIONS
    // short-circuit returns its own response first), but the route
    // bindings still register it; a future PR scoping down or
    // removing `cors_middleware` would resurrect this handler with
    // the raw-env-bind bug (multi-origin deployments emit
    // comma-separated ACAO, browsers reject). Preventive parity:
    // validate request Origin against allowlist, echo back if
    // allowed, omit if not, append `Vary: Origin`.
    async fn cors_options(headers: axum::http::HeaderMap) -> impl axum::response::IntoResponse {
        use axum::body::Body;

        let echoed_origin: Option<String> = headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .filter(|o| talos_config::is_allowed_origin(o))
            .map(|s| s.to_string());

        // MCP-1057: canonical CORS header consts.
        let mut builder = axum::response::Response::builder()
            .status(axum::http::StatusCode::OK)
            .header(header::ACCESS_CONTROL_ALLOW_METHODS, CORS_ALLOW_METHODS)
            .header(header::ACCESS_CONTROL_ALLOW_HEADERS, CORS_ALLOW_HEADERS)
            .header(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true")
            .header(header::ACCESS_CONTROL_MAX_AGE, CORS_MAX_AGE)
            .header(header::VARY, "Origin");
        if let Some(o) = &echoed_origin {
            builder = builder.header(header::ACCESS_CONTROL_ALLOW_ORIGIN, o);
        }
        builder
            .body(Body::empty())
            .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
    }

    // ---------- Axum router ----------
    // Create GraphQL routes with API rate limiting and CSRF protection
    // GraphiQL playground is only enabled in development for security
    let is_production = config::is_production();

    let graphql_route = if is_production {
        // Production: POST only (no GraphiQL playground)
        post(graphql_handler).options(cors_options)
    } else {
        // Development: POST + GET for GraphiQL playground
        post(graphql_handler)
            .options(cors_options)
            .get(graphql_playground)
    };

    let graphql_routes = Router::new()
        .route("/graphql", graphql_route)
        .route("/ws", get(websocket_handler))
        // Limit request body — prevents oversized GraphQL documents from
        // exhausting memory before the query depth/complexity limits fire.
        // L5: shares `csrf::GRAPHQL_MAX_BODY_BYTES` with the CSRF middleware's
        // dev body-buffer cap so the two limits can never silently diverge.
        .layer(DefaultBodyLimit::max(csrf::GRAPHQL_MAX_BODY_BYTES))
        // Opt-in request idempotency. Registered BEFORE the CSRF/rate-limit
        // layers so it is INNER of them (they run first); a request without an
        // `Idempotency-Key` header takes a zero-touch passthrough, so existing
        // traffic is unaffected. Present + valid key → exactly-once via the
        // begin/complete reservation (closes the double-execution window on
        // retried mutations like triggerWorkflow). `idempotency_service` is
        // `None` when Redis is unconfigured → the middleware passes through.
        .layer(from_fn(idempotency::idempotency_middleware))
        .layer(Extension(idempotency_service.clone()))
        // CSRF protection (production only for mutations, lenient in dev)
        .layer(from_fn(csrf::csrf_protection_graphql))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()))
        .layer(Extension(auth_service.clone()))
        .layer(Extension(schema.clone()));

    // Create webhook routes with webhook rate limiting and size limits
    let webhook_routes = Router::new()
        .route("/webhooks/{id}", post(webhooks::webhook_handler))
        // Limit webhook body size to 1MB to prevent memory exhaustion DoS
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(webhook_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Create authenticated routes for human-in-the-loop approvals
    // MCP-1158 (2026-05-16): tight body limit. `ApprovalPayload` is
    // `{ approved: bool }` — ~16 bytes on the wire. Pre-fix the route
    // inherited axum's 2 MiB default which let an authenticated user
    // (or compromised account) burn ~10 ms of JSON-parse CPU per
    // request × rate-limit budget = real DoS pressure on controller
    // heap, even with auth gating. The unauthenticated sibling
    // `/approvals/{token}/{action}` already had a 4 KiB explicit
    // cap — this was the inverted-threat-model side of that pair
    // (authenticated endpoint with 500x more body slack than the
    // public one for an identical-shape action). Same trust-boundary
    // input-cap class as MCP-1148 (URL byte cap) and MCP-1013/1014
    // (XML/JSON/body byte caps).
    let approval_routes = Router::new()
        .route(
            "/api/approvals/{execution_id}",
            post(webhooks::approval_handler),
        )
        .layer(DefaultBodyLimit::max(4096))
        .layer(from_fn(rest_auth_middleware))
        .layer(Extension(auth_service.clone()))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Create OAuth routes (no rate limiting needed - redirects only)
    let oauth_routes = Router::new()
        .route("/auth/oauth/{provider}/login", get(oauth_login_handler))
        .route(
            "/auth/oauth/{provider}/callback",
            get(oauth_callback_handler),
        )
        .layer(Extension(oauth_service.clone()))
        .layer(Extension(auth_service.clone()))
        .layer(Extension(google_calendar_service.clone()));

    // Create Slack API proxy routes
    // NOTE: Layers execute in REVERSE order (bottom-up)
    // MCP-1158 (2026-05-16): tight body limit. `SlackApiParams` is
    // `{ bot_token: String, endpoint: Option<String> }` — bot_token
    // is a fixed-format ~80-char Slack secret, endpoint a short API
    // path (~100 chars). Semantic ceiling ~200 bytes; 8 KiB explicit
    // limit gives ~40x headroom for future fields without inheriting
    // axum's 2 MiB default. Same audit class as the approval_routes
    // fix above — authenticated REST POSTs with tiny payloads.
    let slack_api_routes = Router::new()
        // MCP-976: POST so the bot_token in the JSON body doesn't land
        // in nginx access logs / browser history / referer headers
        // as it would on a GET ?bot_token= query. Also matches the
        // frontend (SlackBrowser.tsx) which has always POSTed JSON.
        .route("/api/slack/channels", post(slack::list_channels_handler))
        .route("/api/slack/users", post(slack::list_users_handler))
        .route("/api/slack/apps/create", post(slack::create_app_handler))
        .with_state(slack_api_client.clone())
        .layer(DefaultBodyLimit::max(8192))
        .layer(from_fn(rest_auth_middleware)) // Runs 5th (last) - needs auth_service extension
        .layer(Extension(auth_service.clone())) // Runs 4th - provides auth_service to middleware above
        .layer(from_fn(rate_limit::rate_limit_middleware)) // Runs 3rd
        .layer(Extension(api_limiter.clone())) // Runs 2nd
        .layer(Extension(whitelist.clone())); // Runs 1st (first)

    // Create Slack integration management routes
    // NOTE: Layers execute in REVERSE order (bottom-up)
    // So layer added LAST runs FIRST!
    let slack_integration_routes = Router::new()
        .route(
            "/api/slack/integrations",
            get(slack::list_integrations_handler),
        )
        .route(
            "/api/slack/integrations/{id}",
            get(slack::get_integration_handler),
        )
        .route(
            "/api/slack/integrations/{id}",
            axum::routing::delete(slack::disconnect_integration_handler),
        )
        .route("/api/slack/connect", get(slack::connect_slack_handler))
        .with_state(slack_integration_service.clone())
        .layer(from_fn(rest_auth_middleware)) // Runs 5th (last) - needs auth_service extension
        .layer(Extension(auth_service.clone())) // Runs 4th - provides auth_service to middleware above
        .layer(from_fn(rate_limit::rate_limit_middleware)) // Runs 3rd
        .layer(Extension(api_limiter.clone())) // Runs 2nd
        .layer(Extension(whitelist.clone())); // Runs 1st (first)

    // Slack OAuth callback — NO auth middleware (mirrors gmail/atlassian).
    // Cross-site redirects from slack.com don't carry the session cookie
    // (SameSite=Strict), so the auth'd router above 401'd the callback before
    // `slack_callback_handler` ran — breaking the Slack connect flow. The
    // handler authenticates via the state token (bound to user_id at
    // /connect time, which IS behind auth) — its signature takes no
    // `Extension<Uuid>`, identical to the working gmail/atlassian callbacks.
    let slack_callback_route = Router::new()
        .route("/api/slack/callback", get(slack::slack_callback_handler))
        .with_state(slack_integration_service.clone())
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Create Gmail integration management routes
    // NOTE: Layers execute in REVERSE order (bottom-up)
    let gmail_integration_routes = Router::new()
        .route(
            "/api/gmail/integrations",
            get(gmail::list_integrations_handler),
        )
        .route(
            "/api/gmail/integrations/{id}",
            get(gmail::get_integration_handler),
        )
        .route(
            "/api/gmail/integrations/{id}",
            axum::routing::delete(gmail::disconnect_integration_handler),
        )
        .route("/api/gmail/connect", get(gmail::connect_gmail_handler))
        .with_state(gmail_integration_service.clone())
        .layer(from_fn(rest_auth_middleware)) // Runs 5th (last) - needs auth_service extension
        .layer(Extension(auth_service.clone())) // Runs 4th - provides auth_service to middleware above
        .layer(from_fn(rate_limit::rate_limit_middleware)) // Runs 3rd
        .layer(Extension(api_limiter.clone())) // Runs 2nd
        .layer(Extension(whitelist.clone())); // Runs 1st (first)

    // Gmail OAuth callback — NO auth middleware.
    // Cross-site redirects from accounts.google.com don't carry session cookies
    // (SameSite policy). The user is identified via the state token instead.
    let gmail_callback_route = Router::new()
        .route("/api/gmail/callback", get(gmail::gmail_callback_handler))
        .with_state(gmail_integration_service.clone())
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Create Google Cloud integration management routes (authenticated).
    // NOTE: Layers execute in REVERSE order (bottom-up).
    let gcp_integration_routes = Router::new()
        .route(
            "/api/gcp/integrations",
            get(google_cloud::list_integrations_handler),
        )
        .route(
            "/api/gcp/integrations/{id}",
            get(google_cloud::get_integration_handler),
        )
        .route(
            "/api/gcp/integrations/{id}",
            axum::routing::delete(google_cloud::disconnect_integration_handler),
        )
        .route("/api/gcp/connect", get(google_cloud::connect_gcp_handler))
        .route(
            "/api/gcp/projects",
            get(google_cloud::list_projects_handler),
        )
        .with_state(google_cloud_integration_service.clone())
        // Write-tier (provisioning) consent uses the SAME connect handler with
        // the write-service state — separate route, separate OAuth consent.
        .merge(
            Router::new()
                .route(
                    "/api/gcp/connect-write",
                    get(google_cloud::connect_gcp_handler),
                )
                .with_state(google_cloud_write_service.clone()),
        )
        // Full-tier (Phase D impersonation base) consent — broad cloud-platform,
        // host-reserved. Same connect handler, full-service state.
        .merge(
            Router::new()
                .route(
                    "/api/gcp/connect-full",
                    get(google_cloud::connect_gcp_handler),
                )
                .with_state(google_cloud_full_service.clone()),
        )
        .layer(from_fn(rest_auth_middleware)) // Runs 5th (last) - needs auth_service extension
        .layer(Extension(auth_service.clone())) // Runs 4th - provides auth_service to middleware above
        .layer(from_fn(rate_limit::rate_limit_middleware)) // Runs 3rd
        .layer(Extension(api_limiter.clone())) // Runs 2nd
        .layer(Extension(whitelist.clone())); // Runs 1st (first)

    // Google Cloud OAuth callback — NO auth middleware.
    // Cross-site redirects from accounts.google.com don't carry session cookies
    // (SameSite policy). The user is identified via the state token instead.
    // BOTH consent tiers share this registered redirect URI; the handler
    // routes by the state token's provider.
    let gcp_callback_route = Router::new()
        .route("/api/gcp/callback", get(google_cloud::gcp_callback_handler))
        .with_state(std::sync::Arc::new(google_cloud::GcpOAuthServices {
            read: google_cloud_integration_service.clone(),
            write: google_cloud_write_service.clone(),
            full: google_cloud_full_service.clone(),
        }))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // GitHub App connect — initiate (authenticated). Returns the install URL.
    // Plus the authenticated installations list (for the Integrations UI).
    let github_connect_route = Router::new()
        .route(
            "/api/github/connect",
            get(talos_github_connect::connect_github_handler),
        )
        .route(
            "/api/github/installations",
            get(talos_github_connect::list_github_installations_handler),
        )
        .with_state(github_connect_service.clone())
        .layer(from_fn(rest_auth_middleware)) // injects Extension<Uuid>
        .layer(Extension(auth_service.clone()))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // GitHub App Setup-URL callback — NO auth middleware. A cross-site redirect
    // from github.com carries no SameSite=Strict session cookie; the user is
    // recovered from the single-use state token instead (B2b-2).
    let github_setup_callback_route = Router::new()
        .route(
            "/api/github/setup",
            get(talos_github_connect::github_setup_callback_handler),
        )
        .with_state(github_connect_service.clone())
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Gmail watch-channel management routes (user-scoped). Only wired
    // when the push service is configured — otherwise the state
    // doesn't exist to manage.
    // MCP-1159 (2026-05-16): 16 KiB body cap (sibling sweep to
    // MCP-1158). `CreateGmailWatchRequest` is `{ integration_id, label_ids?,
    // module_id? }` where label_ids is bounded by Gmail's
    // per-watch limit (50 labels × ~100 chars + framing ≈ 6 KiB worst
    // case). 16 KiB gives ~2.5x headroom. Renew/test handlers take no
    // body but inherit the same cap.
    let gmail_watch_channel_routes = gmail_watch_service.as_ref().map(|svc| {
        Router::new()
            .route(
                "/api/gmail/watch-channels",
                get(gmail::handlers::list_watch_channels_handler),
            )
            .route(
                "/api/gmail/watch-channels",
                post(gmail::handlers::create_watch_channel_handler),
            )
            .route(
                "/api/gmail/watch-channels/{channel_uuid}/renew",
                post(gmail::handlers::renew_watch_channel_handler),
            )
            .route(
                "/api/gmail/watch-channels/{channel_uuid}/test",
                post(gmail::handlers::test_watch_channel_handler),
            )
            .route(
                "/api/gmail/watch-channels/{channel_uuid}",
                axum::routing::delete(gmail::handlers::stop_watch_channel_handler),
            )
            .with_state(svc.clone())
            .layer(DefaultBodyLimit::max(16 * 1024))
            .layer(from_fn(rest_auth_middleware))
            .layer(Extension(auth_service.clone()))
            .layer(from_fn(rate_limit::rate_limit_middleware))
            .layer(Extension(api_limiter.clone()))
            .layer(Extension(whitelist.clone()))
    });

    // Pub/Sub push receiver. PUBLIC — no session auth. JWT from
    // Google's OIDC keys is the sole authenticator (see
    // gmail::pubsub_jwt). Only wired when both the verifier and
    // watch service are available.
    let gmail_pubsub_route =
        if let (Some(verifier), Some(watch)) = (&gmail_pubsub_verifier, &gmail_watch_service) {
            // Dispatch context is optional — when NATS or the
            // worker shared key aren't configured, the push handler
            // still verifies + syncs but doesn't publish WASM jobs.
            // That's useful for bootstrap / dev-without-worker
            // setups; production always has both.
            let dispatch_ctx: Option<gmail::dispatch::GmailDispatchContext> =
                match (nats_client.as_ref(), worker_shared_key.as_ref()) {
                    (Some(nats), Some(key)) => Some(gmail::dispatch::GmailDispatchContext {
                        registry: std::sync::Arc::new(registry::ModuleRegistry::new(
                            db_pool.clone(),
                            redis_client.clone(),
                        )),
                        execution_service: module_execution_service.clone(),
                        nats: nats.clone(),
                        worker_shared_key: key.clone(),
                        redis: redis_client.clone(),
                        db_pool: db_pool.clone(),
                        secrets_manager: Some(secrets_manager.clone()),
                        // RFC 0010 P3 (M4): shared claim-based-sealing handle.
                        sealing_handle: module_sealing_handle.clone(),
                    }),
                    _ => {
                        tracing::warn!(
                            "Gmail push dispatch disabled (NATS or WORKER_SHARED_KEY missing); \
                             pushes will sync + advance cursor but NOT run WASM modules"
                        );
                        None
                    }
                };

            let state = std::sync::Arc::new(gmail::handlers::PubsubHandlerState {
                verifier: verifier.clone(),
                watch_service: watch.clone(),
                dispatch: dispatch_ctx,
            });
            Some(
                Router::new()
                    .route(
                        "/api/gmail/pubsub",
                        post(gmail::handlers::pubsub_push_handler),
                    )
                    .with_state(state)
                    // MCP-1159 (2026-05-16): 64 KiB body cap on the
                    // PUBLIC Pub/Sub push receiver. The envelope shape
                    // is fixed by Google (`{ message: { data: base64,
                    // messageId, publishTime }, subscription }`) where
                    // `data` is a base64 JSON of `{ emailAddress,
                    // historyId }` — realistic total <5 KiB. Without
                    // this layer the receiver inherited axum's 2 MiB
                    // default; a forged-Bearer attacker (or a Google
                    // mis-routed push) could waste serde_json parse
                    // CPU on multi-MB bodies before JWT verify even
                    // runs. JWT verification fires AFTER body extract
                    // here — the cap is the only thing standing
                    // between an unauthenticated POST and a multi-MB
                    // parse. 64 KiB gives 12x headroom over the
                    // realistic ceiling for future envelope extensions.
                    .layer(DefaultBodyLimit::max(64 * 1024))
                    .layer(from_fn(rate_limit::rate_limit_middleware))
                    .layer(Extension(webhook_limiter.clone()))
                    .layer(Extension(whitelist.clone())),
            )
        } else {
            None
        };

    // Admin-only gmail operations. Same two-gate model as gcal:
    // ENABLE_ADMIN_OPS=1 + X-Admin-Secret header.
    let gmail_admin_routes = gmail_watch_service.as_ref().map(|svc| {
        Router::new()
            .route("/api/admin/gmail/watch", post(gmail::admin::create_watch))
            .route("/api/admin/gmail/stop-all", post(gmail::admin::stop_all))
            .with_state(svc.clone())
            .layer(from_fn(rate_limit::rate_limit_middleware))
            .layer(Extension(api_limiter.clone()))
            .layer(Extension(whitelist.clone()))
    });

    // ---------- Google Cloud watch-channel routes (user-scoped) ----------
    // Only wired when the push service is configured (GCP_PUBSUB_AUDIENCE
    // set). 16 KiB body cap: `CreateGcpWatchRequest` is a handful of
    // small fields (uuids + an SA email + a display name); the
    // renew-less test/stop handlers take no body but inherit the cap.
    let gcp_watch_channel_routes = gcp_watch_service.as_ref().map(|svc| {
        Router::new()
            .route(
                "/api/gcp/watch-channels",
                get(google_cloud::handlers::list_watch_channels_handler),
            )
            .route(
                "/api/gcp/watch-channels",
                post(google_cloud::handlers::create_watch_channel_handler),
            )
            .route(
                "/api/gcp/watch-channels/{channel_uuid}/test",
                post(google_cloud::handlers::test_watch_channel_handler),
            )
            .route(
                "/api/gcp/watch-channels/{channel_uuid}",
                axum::routing::delete(google_cloud::handlers::stop_watch_channel_handler),
            )
            .with_state(svc.clone())
            .layer(DefaultBodyLimit::max(16 * 1024))
            .layer(from_fn(rest_auth_middleware))
            .layer(Extension(auth_service.clone()))
            .layer(from_fn(rate_limit::rate_limit_middleware))
            .layer(Extension(api_limiter.clone()))
            .layer(Extension(whitelist.clone()))
    });

    // Cloud Monitoring push receiver. PUBLIC — no session auth. The
    // Google-signed OIDC JWT (audience + per-watch service account) is
    // the sole authenticator (see google_cloud::handlers). Only wired
    // when the verifier, watch service, AND audience are all present.
    let gcp_pubsub_route = if let (Some(verifier), Some(watch), Some(audience)) = (
        &gcp_pubsub_verifier,
        &gcp_watch_service,
        &gcp_pubsub_audience,
    ) {
        let dispatch_ctx: Option<google_cloud::dispatch::GcpDispatchContext> =
            match (nats_client.as_ref(), worker_shared_key.as_ref()) {
                (Some(nats), Some(key)) => Some(google_cloud::dispatch::GcpDispatchContext {
                    registry: std::sync::Arc::new(registry::ModuleRegistry::new(
                        db_pool.clone(),
                        redis_client.clone(),
                    )),
                    execution_service: module_execution_service.clone(),
                    nats: nats.clone(),
                    worker_shared_key: key.clone(),
                    redis: redis_client.clone(),
                    db_pool: db_pool.clone(),
                    integrations: google_cloud_integration_service.clone(),
                    secrets_manager: Some(secrets_manager.clone()),
                    // RFC 0010 P3 (M4): shared claim-based-sealing handle —
                    // the sibling the original M4 sweep missed (found live
                    // 2026-07-17: first real Pub/Sub push refused under
                    // `required`).
                    sealing_handle: module_sealing_handle.clone(),
                }),
                _ => {
                    tracing::warn!(
                        "GCP push dispatch disabled (NATS or WORKER_SHARED_KEY missing); \
                         pushes will be recorded but NOT run WASM modules"
                    );
                    None
                }
            };

        let state = std::sync::Arc::new(google_cloud::handlers::PubsubHandlerState {
            verifier: verifier.clone(),
            expected_audience: audience.clone(),
            watch_service: watch.clone(),
            dispatch: dispatch_ctx,
        });
        Some(
            Router::new()
                .route(
                    "/api/gcp/pubsub/{watch_token}",
                    post(google_cloud::handlers::pubsub_push_handler),
                )
                .with_state(state)
                // 256 KiB body cap on the PUBLIC push receiver. Unlike
                // Gmail's tiny `{ emailAddress, historyId }` envelope, a
                // Cloud Monitoring incident carries documentation /
                // policy / condition text that can run to tens of KiB.
                // 256 KiB gives generous headroom while still bounding an
                // unauthenticated multi-MB parse (JWT verify runs AFTER
                // body extract — the cap is the only guard before it).
                // Sizing rationale mirrors MCP-1159.
                .layer(DefaultBodyLimit::max(256 * 1024))
                .layer(from_fn(rate_limit::rate_limit_middleware))
                .layer(Extension(webhook_limiter.clone()))
                .layer(Extension(whitelist.clone())),
        )
    } else {
        None
    };

    // Admin-only GCP operations. Same two-gate model as gmail/gcal.
    let gcp_admin_routes = gcp_watch_service.as_ref().map(|svc| {
        Router::new()
            .route(
                "/api/admin/gcp/watch",
                post(google_cloud::admin::create_watch),
            )
            .route(
                "/api/admin/gcp/stop-all",
                post(google_cloud::admin::stop_all),
            )
            .with_state(svc.clone())
            .layer(from_fn(rate_limit::rate_limit_middleware))
            .layer(Extension(api_limiter.clone()))
            .layer(Extension(whitelist.clone()))
    });

    // Create Gmail API proxy routes
    // NOTE: Layers execute in REVERSE order (bottom-up)
    let gmail_api_routes = Router::new()
        .route("/api/gmail/labels", get(gmail::list_labels_handler))
        .route("/api/gmail/profile", get(gmail::get_profile_handler))
        .with_state(gmail_api_client.clone())
        .layer(from_fn(rest_auth_middleware)) // Runs 5th (last) - needs auth_service extension
        .layer(Extension(auth_service.clone())) // Runs 4th - provides auth_service to middleware above
        .layer(from_fn(rate_limit::rate_limit_middleware)) // Runs 3rd
        .layer(Extension(api_limiter.clone())) // Runs 2nd
        .layer(Extension(whitelist.clone())); // Runs 1st (first)

    // Create Atlassian (Jira) integration routes (auth-protected)
    // NOTE: Layers execute in REVERSE order (bottom-up)
    let atlassian_integration_routes = Router::new()
        .route(
            "/api/atlassian/integrations",
            get(atlassian::list_integrations_handler),
        )
        .route(
            "/api/atlassian/integrations/{id}",
            axum::routing::delete(atlassian::disconnect_integration_handler),
        )
        .route("/api/atlassian/connect", get(atlassian::connect_handler))
        .with_state(atlassian_integration_service.clone())
        .layer(from_fn(rest_auth_middleware))
        .layer(Extension(auth_service.clone()))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Atlassian OAuth callback — NO auth middleware.
    // Cross-site redirects from auth.atlassian.com don't carry session cookies
    // (SameSite policy). The user is identified via the state token instead.
    let atlassian_callback_route = Router::new()
        .route("/api/atlassian/callback", get(atlassian::callback_handler))
        .with_state(atlassian_integration_service.clone())
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Briefing HTML endpoint — authenticated, returns latest morning briefing as HTML.
    // MCP-680: SecretsManager Extension lets the handler decrypt
    // `output_data_enc` on production deploys (handler returned 404 for
    // every user pre-fix because the SELECT filtered plaintext-only).
    let briefing_routes = Router::new()
        .route(
            "/api/briefings/latest",
            get(integrations::latest_briefing_handler),
        )
        .layer(from_fn(rest_auth_middleware))
        .layer(Extension(auth_service.clone()))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()))
        .layer(Extension(secrets_manager.clone()));

    // Create Google Calendar integration management routes (auth‑protected)
    // NOTE: Layers execute in REVERSE order (bottom‑up)
    let google_calendar_routes = Router::new()
        .route(
            "/api/google-calendar/integrations",
            get(google_calendar::handlers::list_integrations_handler),
        )
        .route(
            "/api/google-calendar/integrations/{id}",
            get(google_calendar::handlers::get_integration_handler),
        )
        .route(
            "/api/google-calendar/integrations/{id}",
            axum::routing::delete(google_calendar::handlers::disconnect_integration_handler),
        )
        .route(
            "/api/google-calendar/integrations/{id}/calendars",
            get(google_calendar::handlers::list_calendars_handler),
        )
        .route(
            "/api/google-calendar/watch/create",
            post(google_calendar::handlers::create_watch_handler),
        )
        .route(
            "/api/google-calendar/watch-channels",
            get(google_calendar::handlers::list_watch_channels_handler),
        )
        .route(
            "/api/google-calendar/watch-channels/{channel_uuid}/renew",
            post(google_calendar::handlers::renew_watch_channel_handler),
        )
        .route(
            "/api/google-calendar/watch-channels/{channel_uuid}/test",
            post(google_calendar::handlers::test_watch_channel_handler),
        )
        .route(
            "/api/google-calendar/watch-channels/{channel_uuid}",
            axum::routing::delete(google_calendar::handlers::stop_watch_channel_handler),
        )
        // Dedicated Calendar OAuth connect (authenticated). Returns the Google
        // authorize URL; identity is bound into the CSRF state token so the
        // (unauthenticated) callback recovers the user from the token.
        .route(
            "/api/google-calendar/connect",
            get(google_calendar::handlers::connect_calendar_handler),
        )
        .with_state(google_calendar_service.clone())
        // MCP-1159 (2026-05-16): 8 KiB body cap. `CreateWatchRequest`
        // is `{ integration_id: Uuid, calendar_id: String, webhook_url:
        // Option<String> }` — UUID (36) + calendar_id (email-shaped
        // ~80 or "primary") + webhook URL (~200 chars). ~500 bytes
        // worst case; 8 KiB cap is ~16x headroom. Renew/test routes
        // take no body. Same sibling-sweep pattern as the gmail
        // watch-channel routes above (MCP-1158 / MCP-1159 family).
        .layer(DefaultBodyLimit::max(8 * 1024))
        .layer(from_fn(rest_auth_middleware)) // Runs 5th (last) - needs auth_service extension
        .layer(Extension(auth_service.clone())) // Runs 4th - provides auth_service to middleware above
        .layer(from_fn(rate_limit::rate_limit_middleware)) // Runs 3rd
        .layer(Extension(api_limiter.clone())) // Runs 2nd
        .layer(Extension(whitelist.clone())); // Runs 1st (first)

    // Public human-in-the-loop approval gate routes.
    // Authentication is the cryptographically random token embedded in the URL.
    // Rate-limited with the webhook limiter to prevent enumeration.
    let approval_gate_routes = Router::new()
        .route(
            "/approvals/{token}/{action}",
            // GET renders a confirmation page with a POST form — keeps
            // the action unsafe (link previews, prefetchers, proxies
            // can GET a shared URL without side effects). POST actually
            // resolves the gate + triggers the continuation workflow.
            get(webhooks::approval_gate_preview).post(webhooks::approval_gate_handler),
        )
        .layer(DefaultBodyLimit::max(4096))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(webhook_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Public one-click ops-alert severity-correction routes (email
    // capability URLs). Same trust model as the approval gates above:
    // the cryptographically random token in the path IS the auth, GET
    // renders a confirm page only (prefetch-safe), POST applies the
    // correction, and the webhook limiter guards enumeration.
    let correction_routes = Router::new()
        .route(
            "/corrections/{token}/{severity}",
            get(webhooks::correction_preview).post(webhooks::correction_apply),
        )
        .layer(DefaultBodyLimit::max(4096))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(webhook_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Public one-click approve/reject routes for SUSPENDED confidence-gate
    // executions (email capability URLs). Same trust model as the approval
    // gates and corrections above: the cryptographically random token in
    // the path IS the auth, GET renders a confirm page only (prefetch-safe),
    // POST applies the decision via the shared record-then-resume path, and
    // the webhook limiter guards enumeration. Distinct from
    // /approvals/{token} (that's the continuation-gate subsystem); these
    // resume a paused execution's checkpoint (submit_workflow_approval path).
    let approval_action_routes = Router::new()
        .route(
            "/approval-actions/{token}/{action}",
            get(webhooks::approval_action_preview).post(webhooks::approval_action_apply),
        )
        .layer(DefaultBodyLimit::max(4096))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(webhook_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Public suspension callback routes.
    // Auth is the 64-hex correlation_id (256-bit random) embedded in the URL.
    // Rate-limited to prevent enumeration brute-force.
    let suspension_callback_routes = Router::new()
        .route(
            "/api/callbacks/{correlation_id}",
            post(webhooks::suspension_callback_handler),
        )
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(webhook_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Google Calendar webhook endpoint (PUBLIC - no auth, uses X-Goog-Channel-Token for verification)
    // Note: redis_client, nats_client, and module_execution_service extensions come from shared app layers
    let google_calendar_webhook_routes = Router::new()
        .route(
            "/api/google-calendar/webhook",
            post(google_calendar::handlers::webhook_notification_handler),
        )
        .with_state(google_calendar_service.clone())
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(webhook_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Dedicated Calendar OAuth callback (PUBLIC — no session auth). Identity is
    // recovered from the single-use CSRF state token inside handle_callback;
    // cross-site redirects from Google don't carry the SameSite session cookie.
    // Rate-limited with the webhook limiter to prevent state-token enumeration.
    let google_calendar_callback_routes = Router::new()
        .route(
            "/api/google-calendar/callback",
            get(google_calendar::handlers::calendar_callback_handler),
        )
        .with_state(google_calendar_service.clone())
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(webhook_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Admin-only gcal operations. Gated by:
    //   1. ENABLE_ADMIN_OPS=1 env var ("big red button" — unset in prod)
    //   2. X-Admin-Secret header vs ADMIN_SECRET_KEY (constant-time compare)
    // Every successful call is audit-logged with event_type="admin_*".
    // Handlers live in google_calendar::admin; see that module for
    // the full defense-in-depth rationale.
    let gcal_admin_routes = Router::new()
        .route(
            "/api/admin/google-calendar/watch",
            post(google_calendar::admin::create_watch),
        )
        .route(
            "/api/admin/google-calendar/stop-all",
            post(google_calendar::admin::stop_all),
        )
        .route(
            "/api/admin/google-calendar/stop-orphan",
            post(google_calendar::admin::stop_orphan),
        )
        .with_state(google_calendar_service.clone())
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Combine all routes

    // Admin routes
    let admin_routes = Router::new()
        .route(
            "/api/admin/secrets/invalidate-cache",
            post(
                |headers: axum::http::HeaderMap,
                 State(secrets_manager): State<std::sync::Arc<secrets::SecretsManager>>| async move {
                    // GATE 1: ENABLE_ADMIN_OPS must be truthy. The gcal admin
                    // path (`google_calendar/admin.rs`) has documented this as the
                    // "big red button" — operators leave it unset in prod so a
                    // leaked ADMIN_SECRET_KEY alone doesn't grant access. Pairing
                    // env-var + secret is the canonical pattern; this route was
                    // missing the env-var half.
                    //
                    // MCP-1064 (2026-05-15): routed through
                    // `talos_config::admin_ops_enabled()` to fix cross-site
                    // drift. Pre-fix this site required the literal `"1"`,
                    // while the gmail / gcal sibling sites accepted
                    // `"1" | "true"`. Operator setting `ENABLE_ADMIN_OPS=true`
                    // would enable gmail/gcal admin but NOT this route. All
                    // three now accept the canonical `true | 1 | yes | on`.
                    if !talos_config::admin_ops_enabled() {
                        tracing::warn!(
                            "admin secrets endpoint hit but ENABLE_ADMIN_OPS is unset/false"
                        );
                        return (axum::http::StatusCode::NOT_FOUND, "Not found");
                    }

                    let admin_secret = std::env::var("ADMIN_SECRET_KEY").unwrap_or_default();
                    let provided_secret = headers.get("X-Admin-Secret").and_then(|h| h.to_str().ok()).unwrap_or("");

                    // GATE 2: constant-time secret compare.
                    //
                    // MCP-983 (2026-05-15): direct ct_eq on slices. Pre-fix
                    // padded both inputs to a 512-byte buffer ("ct_eq always
                    // runs regardless of length, preventing length leakage")
                    // — but when `admin_secret.len() > 512` only the FIRST
                    // 512 bytes participated in the byte comparison. An
                    // attacker who knew those 512 bytes (plus the configured
                    // length, leaked via the explicit `a.len() == b.len()`
                    // check) could authenticate against any longer suffix.
                    // Subtle's slice `ct_eq` returns Choice(0) immediately
                    // on length mismatch and runs constant-time over equal-
                    // length contents; the residual length signal is
                    // sub-jitter for sensibly-sized admin secrets. Same fix
                    // applied to sibling sites talos-gmail/src/admin.rs and
                    // talos-google-calendar/src/admin.rs.
                    use subtle::ConstantTimeEq;
                    let is_match = admin_secret
                        .as_bytes()
                        .ct_eq(provided_secret.as_bytes())
                        .unwrap_u8()
                        == 1;

                    if !admin_secret.is_empty() && is_match {
                        // MCP-800 (2026-05-14): surface invalidate_dek_cache
                        // failures truthfully. Pre-fix `let _ = ...await`
                        // discarded the Result and the admin always saw a
                        // 200 "DEK cache invalidated successfully" — even
                        // when the underlying audit-log write or in-memory
                        // cache mutation failed. This is the admin
                        // operator's primary signal post-DEK-rotation /
                        // post-incident; misleading "success" lets them
                        // believe an actor's WASM-resident plaintext DEK
                        // was purged when it wasn't. Same misleading-
                        // success class as MCP-737 (graph-mutation
                        // handlers) and MCP-738 (duplicate/deploy
                        // workflow). Underlying error is logged at ERROR
                        // server-side; admin sees a generic 500 to avoid
                        // leaking internal failure detail (sqlx schema,
                        // KEK provider state, etc.).
                        match secrets_manager
                            .invalidate_dek_cache(None, "ADMIN_API", None)
                            .await
                        {
                            Ok(_) => (
                                axum::http::StatusCode::OK,
                                "DEK cache invalidated successfully",
                            ),
                            Err(e) => {
                                tracing::error!(
                                    target: "talos_audit",
                                    error = ?e,
                                    "admin invalidate_dek_cache failed — DEK plaintext may still be cached"
                                );
                                (
                                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                    "Failed to invalidate DEK cache",
                                )
                            }
                        }
                    } else {
                        (axum::http::StatusCode::UNAUTHORIZED, "Unauthorized")
                    }
                },
            ),
        )
        .with_state(secrets_manager.clone())
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // The MCP state re-uses the vault-backed Arc built above at line ~1783
    // — a single client instance shared by GraphQL + MCP ensures rotation
    // propagates through both surfaces identically.

    // MCP-680 (2026-05-13): wire SecretsManager so analytics output-reading
    // queries (`get_completed_executions_output` etc.) can decrypt
    // `output_data_enc` rows. Without this the analytics surface would be
    // blind to every completed execution in encryption-enabled deploys
    // (production default) — per-node timing breakdowns showed empty for
    // every workflow.
    let analytics_repo = std::sync::Arc::new(
        analytics_repository::AnalyticsRepository::new(db_pool.clone())
            .with_secrets_manager(secrets_manager.clone()),
    );

    let advanced_repo = std::sync::Arc::new(advanced_repository::AdvancedRepository::new(
        db_pool.clone(),
    ));

    // workflow_repo, module_repo, execution_repo, and actor_repo are
    // constructed earlier (alongside the cross-protocol services) so
    // they're shared with the GraphQL ctx.data wiring. The Arc is
    // cheap to clone here.

    let mcp_routes = mcp::create_router(
        registry.clone(),
        db_pool.clone(),
        runtime.clone(),
        compiler.clone(),
        nats_client.clone(),
        llm_client,
        circuit_breaker.clone(),
        dlp_service.clone(),
        workflow_repo,
        execution_repo,
        analytics_repo,
        advanced_repo,
        actor_repo,
        module_repo,
        secrets_manager.clone(),
        workflow_creation_service.clone(),
        hot_update_service.clone(),
        execution_orchestration_service.clone(),
        workflow_manifest_service.clone(),
        replay_service.clone(),
        inline_compile_service.clone(),
        search_service.clone(),
        failure_analysis_service.clone(),
        actor_lifecycle_service.clone(),
        Some(ollama_client),
    );

    // MCP routes are added separately to avoid the global governor rate limiter.
    // MCP has its own per-agent rate limiter (1000 req/min).
    let mcp_router = Router::new().nest("/mcp", mcp_routes);

    // Probe + scrape routes are merged AFTER the rate-limit layers below, so
    // kubelet liveness/readiness/startup probes and Prometheus scrapes can
    // never be rate-limited. With Traefik on `externalTrafficPolicy: Cluster`,
    // probes share the node IP with all SNAT'd external traffic — without this
    // bypass, a busy site evicts probes from the per-IP bucket, the kubelet
    // marks the pod NotReady, traffic gets a 502, and the cycle repeats.
    //
    // This sub-router needs its own copies of the extensions its handlers
    // depend on (db_pool, redis_client, nats_client) because the Extension
    // layers added to the main router only wrap routes registered before
    // those layers. See is_rate_limit_exempt_path() for the path list — it
    // mirrors the routes here as a defence-in-depth check.
    let probe_routes = Router::new()
        .route("/", get(|| async { "Talos Controller is running" }))
        .route("/health", get(health_check))
        .route("/health/redis", get(health_check_redis))
        .route("/health/nats", get(health_check_nats))
        .route("/live", get(liveness_probe)) // no-nginx-route: kubelet-only probe
        .route("/ready", get(readiness_probe)) // no-nginx-route: kubelet-only probe
        // Prometheus scrape target — returns the full registry in text
        // exposition format. Shared-secret auth via PROMETHEUS_SCRAPE_TOKEN
        // (Bearer). Scrape this on an internal-only Service in K8s; do not
        // expose publicly. See deploy/observability/alerts.yaml for the
        // alert rules that consume these series.
        .route("/metrics/prometheus", get(prometheus_metrics_handler)) // no-nginx-route: in-cluster scrape only
        // Dedicated double-submit CSRF cookie seeder. The frontend GETs
        // this once before its first POST `/graphql` to ensure the cookie
        // is set. Lives in `probe_routes` (no rate limiting, no auth) and
        // sets the Set-Cookie header directly so it doesn't depend on
        // CookieManagerLayer's interaction with merged sub-routers — that
        // layering was unreliable and produced silent no-Set-Cookie
        // responses (debugged 2026-04-25).
        .route("/auth/csrf", get(seed_csrf_handler))
        .layer(Extension(db_pool.clone()))
        .layer(Extension(redis_client.clone()))
        .layer(Extension(nats_client.clone()));

    // RFC 0010 P2 inc.4c: in-cluster worker self-registration. Mounted ONLY when
    // a registration credential scheme is configured — the legacy shared token
    // (TALOS_WORKER_REGISTRATION_TOKEN) and/or bound-token enforcement
    // (TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN=1, provisioning tokens minted via
    // the mint-worker-provisioning-token CLI). Fail-closed: neither ⇒ no route
    // ⇒ 404. Merged after the rate-limit layers like probe_routes, so it
    // carries its own Extensions (db_pool + the auth config) and a small body
    // cap. Access is further restricted to worker pods by the chart
    // NetworkPolicy; it is never exposed via nginx (`no-nginx-route`).
    let worker_reg_shared_token = std::env::var("TALOS_WORKER_REGISTRATION_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(std::sync::Arc::new);
    let worker_reg_require_bound = std::env::var("TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false);
    let internal_routes = if worker_reg_shared_token.is_some() || worker_reg_require_bound {
        tracing::info!(
            require_bound_token = worker_reg_require_bound,
            shared_token_accepted = worker_reg_shared_token.is_some() && !worker_reg_require_bound,
            "Worker self-registration endpoint enabled at POST /internal/worker-key"
        );
        Router::new()
            .route(
                "/internal/worker-key",
                axum::routing::post(register_worker_key_handler),
            ) // no-nginx-route: RFC0010 in-cluster worker self-registration
            .layer(axum::extract::DefaultBodyLimit::max(4096))
            .layer(Extension(db_pool.clone()))
            .layer(Extension(WorkerRegAuth {
                shared_token: worker_reg_shared_token,
                require_bound: worker_reg_require_bound,
            }))
    } else {
        tracing::info!(
            "Worker self-registration endpoint disabled (TALOS_WORKER_REGISTRATION_TOKEN and \
             TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN unset); use the register-worker-identity CLI \
             or TALOS_WORKER_PUBLIC_KEYS env"
        );
        Router::new()
    };

    let app = Router::new()
        // Authenticated user-facing metrics dashboard. Stays inside the
        // rate-limited router; the unauthenticated Prometheus scrape lives
        // in `probe_routes` above.
        .route("/metrics", get(metrics_handler)) // no-nginx-route: authenticated metrics dashboard, accessed via /graphql proxy
        .merge(api_docs::create_docs_router())
        .merge(graphql_routes)
        .merge(webhook_routes)
        .merge(approval_routes)
        .merge(oauth_routes)
        .merge(slack_api_routes)
        .merge(slack_integration_routes)
        .merge(slack_callback_route)
        .merge(admin_routes)
        .merge(gmail_api_routes)
        .merge(gmail_integration_routes)
        .merge(gmail_callback_route)
        .merge(gcp_integration_routes)
        .merge(gcp_callback_route)
        .merge(github_connect_route)
        .merge(github_setup_callback_route);
    // Optional gmail push routes — `None` when GMAIL_PUBSUB_TOPIC
    // wasn't configured at startup.
    let app = if let Some(r) = gmail_watch_channel_routes {
        app.merge(r)
    } else {
        app
    };
    let app = if let Some(r) = gmail_pubsub_route {
        app.merge(r)
    } else {
        app
    };
    let app = if let Some(r) = gmail_admin_routes {
        app.merge(r)
    } else {
        app
    };
    // Optional GCP push routes — `None` when GCP_PUBSUB_AUDIENCE wasn't
    // configured at startup.
    let app = if let Some(r) = gcp_watch_channel_routes {
        app.merge(r)
    } else {
        app
    };
    let app = if let Some(r) = gcp_pubsub_route {
        app.merge(r)
    } else {
        app
    };
    let app = if let Some(r) = gcp_admin_routes {
        app.merge(r)
    } else {
        app
    };
    let app = app
        .merge(atlassian_integration_routes)
        .merge(atlassian_callback_route)
        // Briefing HTML endpoint — authenticated, returns latest morning briefing as HTML
        .merge(briefing_routes)
        // Integration provider registry — public, returns static metadata + config status
        .route(
            "/api/integrations/providers",
            get(integrations::providers_handler),
        )
        // Public endpoint for client configuration (no auth required)
        // The route still needs access to the GoogleCalendarService for the client ID
        // and redirect URI, so we attach the same shared state as the other Google
        // Calendar routes. This keeps the router type uniform and preserves the
        // `into_make_service_with_connect_info` method.
        .merge(
            Router::new()
                .route(
                    "/api/google-calendar/client-config",
                    get(google_calendar::handlers::client_config_handler),
                )
                .with_state(google_calendar_service.clone()),
        )
        .merge(approval_gate_routes)
        .merge(correction_routes)
        .merge(approval_action_routes)
        .merge(suspension_callback_routes)
        .merge(google_calendar_routes)
        .merge(google_calendar_webhook_routes)
        .merge(google_calendar_callback_routes)
        .merge(gcal_admin_routes)
        // M-8 (talos-registry review): /api/registry/publish writes
        // globally-visible catalog rows (`kind='catalog', user_id=NULL`)
        // that every authenticated user can install. The endpoint is
        // operator-only — driven by `scripts/util/talos-publish.py` —
        // and protected at the handler layer by a shared bearer-token
        // check (`REGISTRY_PUBLISH_TOKEN`). Production deploys MUST set
        // the env var or the endpoint refuses POSTs with 503.
        // Single-tenant operators set the token; multi-tenant should
        // disable nginx routing for /api/registry/* entirely.
        .nest(
            "/api/registry",
            registry::api::registry_router().with_state(registry.clone()),
        )
        // Cookie support
        .layer(CookieManagerLayer::new())
        // Add shared extensions for all routes
        .layer(Extension(db_pool.clone()))
        // MCP-1131 (2026-05-16): `.clone()` so `webhook_router` stays
        // in scope for the graceful_shutdown callback below; the
        // shutdown callback calls `webhook_router.shutdown_dlq()`
        // before the tokio runtime aborts the DLQ batch processor.
        // Closes the "DLQ messages in-flight" concern from MCP-667.
        .layer(Extension(webhook_router.clone()))
        // Registry shared with approval gate handler for continuation workflow dispatch
        .layer(Extension(registry.clone()))
        .layer(Extension(redis_client.clone()))
        .layer(Extension(nats_client.clone()))
        .layer(Extension(Some(module_execution_service.clone())))
        .layer(Extension(Some(worker_manager.clone())))
        .layer(Extension(worker_shared_key.clone()))
        // Shared runtime and secrets manager — used by webhook handlers to execute
        // downstream workflow nodes in-process (workflow chaining).
        .layer(Extension(Some(runtime.clone())))
        .layer(Extension(Some(secrets_manager.clone())))
        // Shared orchestration service — the one-click approve/reject email
        // links (/approval-actions/{token}) apply decisions through the same
        // record-then-resume write path as submit_workflow_approval.
        .layer(Extension(Some(execution_orchestration_service.clone())))
        // RFC 0010 P3 (M4): shared claim-based-sealing handle for the
        // Google-Calendar push handler (fire-and-forget module dispatch).
        .layer(Extension(module_sealing_handle.clone()))
        // Trusted proxy list — used by rate_limit_middleware to decide whether to
        // trust X-Forwarded-For headers. Shared across all rate-limited routes.
        .layer(Extension(trusted_proxies));

    // Conditionally add global rate limiting (only in production)
    let app = if config::is_production() {
        app.layer(from_fn(rate_limit::global_rate_limit_middleware))
            .layer(Extension(global_limiter))
    } else {
        tracing::info!("Global rate limiter DISABLED in development mode");
        app
    };

    // Apply tower_governor IP rate limiting only in production.
    // In development the burst of simultaneous GraphQL queries on page load
    // (AuthenticatedApp, Dashboard, WorkflowStatsPanel, etc.) routinely exceeds
    // the 20-token burst cap and produces spurious 429s.
    let app = if config::is_production() {
        app.layer(governor_layer)
    } else {
        tracing::info!("tower_governor IP rate limiter DISABLED in development mode");
        app
    };
    let app = app
        // Merge MCP routes AFTER governor so they're exempt from IP rate limiting
        .merge(mcp_router)
        // Same for probe + scrape routes — see `probe_routes` definition.
        .merge(probe_routes)
        // RFC 0010 P2 inc.4c worker self-registration (empty router when the
        // token is unset, so this merge is a no-op in that mode).
        .merge(internal_routes)
        // Request ID for tracing and audit logging (generates/propagates X-Request-ID)
        .layer(from_fn(request_id::request_id_middleware))
        // Security headers (apply to all responses)
        .layer(from_fn(security_headers::add_security_headers))
        // CORS - must be last layer (runs first) to handle OPTIONS preflight
        .layer(from_fn(cors_middleware));

    Ok(app)
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
