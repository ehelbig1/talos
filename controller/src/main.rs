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
use tokio::sync::broadcast;
use worker::runtime::TalosRuntime;

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

/// Maximum characters of WASM-emitted log content broadcast on the
/// `execution_updates` GraphQL subscription. Mirrors the persistence
/// path's per-row cap (`MAX_MSG_LEN` in
/// `talos_execution_repository::add_workflow_log`); kept in lockstep
/// so the live channel can't carry more than the persisted row.
const MAX_BROADCAST_LOG_CHARS: usize = 8 * 1024;

/// Sanitise a WASM-emitted log message for live broadcast on
/// `execution_updates`. Mirrors the pipeline `add_workflow_log` runs
/// before persisting to `workflow_execution_logs.message`:
///   1. char-count truncate to `MAX_BROADCAST_LOG_CHARS`
///   2. strip control chars except newline/tab/carriage return
///   3. DLP redact (`talos_dlp_provider::redact_str`)
///
/// Extracted as a free function so the discipline is unit-testable
/// (the inline call site is otherwise too deep in the NATS subscriber
/// loop to cover without bringing up a NATS test harness).
/// Same MCP-481 / MCP-1011 class — every operator-visible WASM-log
/// surface needs identical scrubbing.
fn scrub_wasm_log_for_broadcast(message: &str) -> String {
    let truncated: String = if message.chars().count() > MAX_BROADCAST_LOG_CHARS {
        let mut s: String = message.chars().take(MAX_BROADCAST_LOG_CHARS).collect();
        s.push_str("... (truncated)");
        s
    } else {
        message.to_string()
    };
    let sanitized: String = truncated
        .chars()
        .filter(|c| !c.is_control() || matches!(*c, '\n' | '\t' | '\r'))
        .collect();
    // 2026-05-28 audit F3 perf follow-up: per-log-line broadcast is a
    // hot path that runs the DLP scrubber per message × per subscriber.
    // The trait-method `redact_str` allocates a fresh String for every
    // pattern even when nothing matches (~14 patterns × `String::from_owned`
    // per call). Switching to the Cow variant keeps the legitimate-log
    // common case allocation-free.
    talos_dlp_provider::redact_str_cow(&sanitized).into_owned()
}

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
                        calls: i64::try_from(u.calls).unwrap_or(i32::MAX as i64) as i32,
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

/// Postgres pool init + migrations + RLS-bypass warning + first-user
/// bootstrap + embedding warmup. Extracted verbatim from `main()`.
async fn init_database() -> anyhow::Result<sqlx::Pool<sqlx::Postgres>> {
    // ---------- Initialise DB ----------
    // Database schema is managed via migrations in /migrations/.
    // Auto-applied at startup so a `make rebuild` is enough — no separate
    // `docker compose run --rm migrate` step needed. Replaces the prior
    // foot-gun where new tables silently went missing on rebuild.
    let db_pool: sqlx::Pool<sqlx::Postgres> = init_pool().await?;

    // RFC 0004 readiness check: warn loudly if the controller's DB role
    // would silently bypass row-level security (superuser / BYPASSRLS).
    // Informational today (RLS isn't enabled until M4); surfaces the
    // misconfiguration before it can turn the tenant-isolation policies
    // into a no-op. One catalog lookup, non-blocking.
    let _rls_role_status = talos_db::warn_if_rls_will_be_bypassed(&db_pool).await;

    // RFC 0004 / RFC 0005 S3 production fail-closed posture. In production,
    // refuse to boot if tenant-isolation RLS would silently be a no-op —
    // unless the operator explicitly acknowledges the weaker posture via
    // TALOS_ALLOW_RLS_DISABLED=1. Mirrors the env-KEK production guard
    // (`prod-kek-guard`). No-op outside production, so dev/test is unaffected.
    talos_db::enforce_production_rls_posture(&db_pool, config::is_production()).await?;

    // Security review 2026-07-19 (P1): the `database` capability world runs
    // guest SQL against this primary pool. In production, refuse to boot unless
    // the `SET LOCAL ROLE` fence (TALOS_RPC_GUEST_ROLE) is configured — or the
    // operator explicitly accepts the unscoped posture via
    // TALOS_ALLOW_UNSCOPED_DB_SANDBOX=1. Mirrors the RLS/env-KEK guards; no-op
    // outside production.
    talos_rpc_subscribers::enforce_production_db_sandbox_posture(config::is_production())?;

    {
        let migrate_start = std::time::Instant::now();
        match sqlx::migrate!("../migrations").run(&db_pool).await {
            Ok(()) => {
                tracing::info!(
                    elapsed_ms = migrate_start.elapsed().as_millis() as u64,
                    "Database migrations applied (or already up-to-date)"
                );
            }
            Err(e) => {
                // Hard-fail: continuing with a stale schema is worse than
                // refusing to boot. Operators get a clear error in logs.
                tracing::error!(error = %e, "Database migrations failed — refusing to start");
                return Err(anyhow::anyhow!("migrations failed: {e}"));
            }
        }
    }

    // First-user bootstrap: if the bootstrap migration ran on an empty DB
    // (the normal fresh-install path), promote the earliest-registered user
    // now so they aren't stuck at the default http-node ceiling. Idempotent —
    // no-op if any user already holds automation-node.
    if let Err(e) = talos_auth::promote_first_user_if_needed(&db_pool, None).await {
        tracing::warn!(
            error = %e,
            "First-user bootstrap promotion failed (non-fatal — users can still register)"
        );
    }

    // Embedding warmup: fire-and-forget so controller startup isn't blocked
    // by a slow (or down) provider. Local providers like Ollama lazy-load
    // models on first request (~5 s cold). Without warmup, the first
    // user-facing write times out, stores `embedding = NULL`, and future
    // semantic searches on that row silently degrade to keyword fallback.
    tokio::spawn(talos_memory::embedding::warmup());

    Ok(db_pool)
}

/// Redis client init (TLS prod gate + connection test). Extracted verbatim
/// from `main()`.
async fn init_redis() -> Option<std::sync::Arc<redis::Client>> {
    // ---------- Initialize Redis client for distributed caching ----------
    let redis_client = if let Ok(redis_url) = std::env::var("REDIS_URL") {
        // SECURITY: In production, enforce TLS (rediss://) and reject plaintext (redis://).
        // This prevents an operator misconfiguration from silently exposing secrets and
        // session tokens over an unencrypted Redis connection.
        // tls-prod-gate-redis
        if crate::config::is_production() && !redis_url.starts_with("rediss://") {
            panic!(
                "REDIS_URL must use 'rediss://' (TLS) in production. \
                 Plain 'redis://' is not allowed. Got scheme: '{}'",
                redis_url.split("://").next().unwrap_or("<unknown>")
            );
        }
        match redis::Client::open(redis_url.as_str()) {
            Ok(client) => {
                // Test connection
                match client.get_multiplexed_async_connection().await {
                    Ok(_) => {
                        // Use `next_back` to avoid iterating the whole iterator when extracting the host part.
                        tracing::info!(
                            "Redis client initialized and connected: {}",
                            redis_url.split('@').next_back().unwrap_or("redis")
                        );
                        Some(std::sync::Arc::new(client))
                    }
                    Err(e) => {
                        tracing::error!("Failed to connect to Redis: {}. WASM cache interface will be unavailable.", e);
                        None
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    "Failed to create Redis client: {}. WASM cache interface will be unavailable.",
                    e
                );
                None
            }
        }
    } else {
        tracing::warn!("REDIS_URL not configured. WASM cache interface will be unavailable.");
        None
    };

    redis_client
}

/// NATS client init (TLS prod gate + authenticated connect). Extracted
/// verbatim from `main()`.
async fn init_nats() -> anyhow::Result<Option<std::sync::Arc<async_nats::Client>>> {
    // ---------- Initialize NATS client for message queues ----------
    let nats_client = if let Ok(nats_url) = std::env::var("NATS_URL") {
        // SECURITY: In production, REFUSE to start on a plaintext NATS URL. The
        // message bus carries HMAC-signed job payloads AND decrypted memory
        // values (potential PHI) in RPC replies — cleartext on the wire is a
        // transmission-security violation (HIPAA §164.312(e) / SOC2 CC6.7).
        // tls-prod-gate-nats
        if crate::config::is_production()
            && !nats_url.starts_with("tls://")
            && !nats_url.starts_with("nats+tls://")
        {
            return Err(anyhow::anyhow!(
                "NATS_URL must use TLS (tls:// or nats+tls://) in production — refusing to \
                 start. Got scheme: '{}'.",
                nats_url.split("://").next().unwrap_or("<unknown>")
            ));
        }

        // SECURITY: Use authenticated connection when NATS_USER + NATS_PASSWORD are set.
        // MCP-710 (2026-05-13): empty-env class. Pre-fix `NATS_USER=""`
        // (helm placeholder) yielded `Some("")`, making `authenticated`
        // true at line ~353; the connect path then sent empty credentials
        // to NATS which rejected with a confusing auth error rather
        // than the documented "no credentials" fallback. Same
        // empty-env class as MCP-590/591/592/653/etc.
        let nats_user = std::env::var("NATS_USER").ok().filter(|v| !v.is_empty());
        let nats_password = std::env::var("NATS_PASSWORD")
            .ok()
            .filter(|v| !v.is_empty());

        // Sanitize the URL before logging — it may contain embedded credentials
        // (e.g. `nats://user:secret@host:4222`).  Strip the userinfo component.
        let nats_url_safe = {
            let mut u = nats_url.clone();
            if let Some(at) = u.find('@') {
                // Find the scheme end (after "://") to preserve it.
                let scheme_end = u.find("://").map(|i| i + 3).unwrap_or(0);
                u.replace_range(scheme_end..at + 1, "[credentials]@");
            }
            u
        };

        let authenticated = nats_user.is_some();
        let connect_result = match (nats_user, nats_password) {
            (Some(user), Some(pass)) => {
                // apply_nats_ca adds the in-cluster NATS CA + requires TLS when
                // NATS_CA_FILE is set (tls:// URL); no-op otherwise.
                let opts = async_nats::ConnectOptions::new()
                    .user_and_password(user, pass)
                    .request_timeout(Some(std::time::Duration::from_secs(86400 * 7))); // 7 days for governance approvals
                talos_nats_tls::apply_nats_ca(opts).connect(&nats_url).await
            }
            _ => {
                if crate::config::is_production() {
                    tracing::warn!(
                        "NATS connecting without authentication (NATS_USER/NATS_PASSWORD not set). \
                         In production, configure NATS credentials to prevent unauthorized access \
                         to the job queue."
                    );
                }
                let opts = async_nats::ConnectOptions::new()
                    .request_timeout(Some(std::time::Duration::from_secs(86400 * 7))); // 7 days for governance approvals
                talos_nats_tls::apply_nats_ca(opts).connect(&nats_url).await
            }
        };

        match connect_result {
            Ok(client) => {
                tracing::info!(
                    nats_url = %nats_url_safe,
                    authenticated,
                    "NATS client initialized and connected"
                );
                // The audit ledger subscriber is started AFTER the secrets
                // manager is initialized (see below) so it can be handed an
                // Arc<SecretsManager> for the KEK-backed OTLP auth-header
                // envelope (v3). Don't start it here.
                Some(std::sync::Arc::new(client))
            }
            Err(e) => {
                tracing::error!(
                    "Failed to connect to NATS: {}. WASM messaging interface will be unavailable.",
                    e
                );
                None
            }
        }
    } else {
        tracing::warn!("NATS_URL not configured. WASM messaging interface will be unavailable.");
        None
    };

    Ok(nats_client)
}

/// Module registry + compilation service + secrets manager (KEK provider
/// selection). Extracted verbatim from `main()`.
async fn build_core_services(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    redis_client: Option<std::sync::Arc<redis::Client>>,
) -> anyhow::Result<CoreServices> {
    // ---------- Initialize node creation services ----------
    let registry = std::sync::Arc::new(ModuleRegistry::new(db_pool.clone(), redis_client.clone()));
    // MCP-922 (2026-05-14): `talos_templates::TemplateGenerator` was
    // historically instantiated here and `.data(generator)`-injected
    // into GraphQL ctx, but no resolver ever extracted it via
    // `ctx.data::<Arc<TemplateGenerator>>()`. Production template
    // rendering goes through `talos_compilation::render_template`
    // (which has stricter `validate_config_values` + the
    // `// handlebars: true` opt-in gate). Removing the dead Arc
    // allocation + GraphQL ctx slot. The crate stays for the
    // `controller/tests/module_template_tests.rs` integration tests
    // that pin built-in template render correctness.
    // Allow the compilation directory to be overridden via COMPILE_DIR env var.
    // Defaults to "/tmp/talos-compilations" for backward compatibility.
    // MCP-631: empty-env hardening — empty value would produce an empty
    // path and every compile attempt would fail at FS-write time.
    let compile_dir = talos_config::get_env("COMPILE_DIR", "/tmp/talos-compilations");
    // CompilationService::new signature evolved to take a CompilationEventSender
    // for streaming progress events. main.rs creates a no-op broadcast channel
    // here — production paths that need the event stream wire it up via the
    // GraphQL subscription layer; this dummy is fine for the binary's startup
    // boilerplate (compilation events get dropped if no receiver is listening).
    let (compilation_event_tx, _) =
        tokio::sync::broadcast::channel::<crate::engine::events::CompilationEvent>(64);
    let compiler = std::sync::Arc::new(CompilationService::new(
        std::path::PathBuf::from(compile_dir),
        compilation_event_tx.clone(),
    ));

    // ---------- Initialize secrets manager ----------
    // KEK provider selection: `KEK_PROVIDER` env var picks the backend
    // that wraps/unwraps DEKs. `env` (default) loads `TALOS_MASTER_KEY`
    // and runs local AES-256-GCM. `vault` calls HashiCorp Vault's
    // transit engine — the master key never leaves Vault. Boot fails
    // closed if `vault` is selected but the health check fails.
    let kek_provider_kind = std::env::var("KEK_PROVIDER")
        .unwrap_or_else(|_| "env".to_string())
        .to_lowercase();
    let (kek_provider, kek_legacy_provider): (
        std::sync::Arc<dyn crate::secrets::kek_provider::KekProvider>,
        Option<std::sync::Arc<dyn crate::secrets::kek_provider::KekProvider>>,
    ) = match kek_provider_kind.as_str() {
        "env" => {
            // P1-B production KEK guard. An env-backed KEK keeps the root key
            // (TALOS_MASTER_KEY) in a Kubernetes Secret AND in process memory,
            // where anyone with `kubectl get secret` or a heap/core dump can
            // recover it — defeating envelope encryption against an insider or
            // dump-exfil threat. Regulated deployments (HIPAA/SOC2/ISO key
            // management) want a KMS-backed KEK (`KEK_PROVIDER=vault`, the chart
            // default) so the root key never leaves Vault.
            //
            // Refuse to boot in production unless the operator explicitly
            // acknowledges the weaker posture. There IS an override (unlike the
            // in-transit-TLS gates) because env-KEK is a legitimate single-host
            // / homelab mode with no Vault — but it must be a deliberate,
            // audited opt-in, not a silent default.
            // prod-kek-guard
            if crate::config::is_production() {
                let allow_env_kek = std::env::var("TALOS_ALLOW_ENV_KEK")
                    .ok()
                    .map(|v| {
                        let v = v.trim();
                        v.eq_ignore_ascii_case("true")
                            || v == "1"
                            || v.eq_ignore_ascii_case("yes")
                            || v.eq_ignore_ascii_case("on")
                    })
                    .unwrap_or(false);
                if !allow_env_kek {
                    return Err(anyhow::anyhow!(
                        "KEK_PROVIDER=env keeps the master key (TALOS_MASTER_KEY) in a Secret + \
                         process memory — refused in production. Use KEK_PROVIDER=vault \
                         (KMS-backed; the chart default) so the root key never leaves Vault. To \
                         run env-KEK in production anyway (e.g. a single-host homelab with no \
                         Vault), set TALOS_ALLOW_ENV_KEK=true to acknowledge the weaker posture."
                    ));
                }
                // Override in use — loud + SIEM-greppable so the weaker posture
                // is visible in audit/alerting, not silently accepted.
                tracing::error!(
                    target: "talos_security",
                    event_kind = "env_kek_in_production",
                    "KEK_PROVIDER=env accepted in production via TALOS_ALLOW_ENV_KEK — the master \
                     key lives in a Secret + process memory (no KMS). Migrate to \
                     KEK_PROVIDER=vault for a compliant key-management posture."
                );
            }
            (
                crate::secrets::kek_provider::env_kek_provider_from_environment()?,
                None,
            )
        }
        "vault" => {
            use anyhow::Context as _;
            let active = crate::secrets::vault_kek_provider::VaultTransitProvider::from_env()?;
            active
                .health_check()
                .await
                .context("Vault transit KEK provider health check failed at startup")?;
            // Phase 4 dual-wrap soak: keep the env-var provider wired
            // as legacy so reads can fall back to encrypted_key for any
            // not-yet-rewrapped row, and writes dual-populate both
            // columns for rollback safety. Disable via
            // KEK_DISABLE_LEGACY=true once Phase 5 ships.
            let disable_legacy = std::env::var("KEK_DISABLE_LEGACY")
                .ok()
                .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
                .unwrap_or(false);
            let legacy = if disable_legacy {
                tracing::info!("KEK_DISABLE_LEGACY=true — running vault-only (no env fallback)");
                None
            } else {
                Some(crate::secrets::kek_provider::env_kek_provider_from_environment()?)
            };
            (std::sync::Arc::new(active), legacy)
        }
        other => {
            return Err(anyhow::anyhow!(
                "Unknown KEK_PROVIDER={:?} — supported values: env, vault",
                other
            ));
        }
    };
    let secrets_manager = std::sync::Arc::new(SecretsManager::with_kek_providers(
        db_pool.clone(),
        kek_provider,
        kek_legacy_provider,
    )?);
    secrets_manager.initialize().await?;
    tracing::info!("Secrets manager initialized");

    Ok(CoreServices {
        registry,
        compiler,
        compilation_event_tx,
        secrets_manager,
    })
}

/// At-rest crypto hook registration + audit-ledger subscriber start.
/// Ordering is load-bearing: the integration_state encryptor and the
/// actor_memory crypto hook MUST be installed before any writes, and the
/// audit-ledger subscriber is deliberately started only after the
/// SecretsManager exists (KEK-backed OTLP auth-header envelope). Extracted
/// verbatim from `main()`.
async fn register_crypto_hooks(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    nats_client: Option<std::sync::Arc<async_nats::Client>>,
    secrets_manager: std::sync::Arc<SecretsManager>,
) -> anyhow::Result<()> {
    // Install the process-wide integration_state value encryptor (encrypt-at-rest
    // for the durable OAuth-token / watch-secret primitive). Every execute_op
    // write is now AEAD-sealed under the per-user org DEK; reads decrypt or fall
    // back to legacy plaintext. Mirrors the set-once GitHub-provider wiring below.
    talos_integration_state::set_integration_state_crypto(secrets_manager.clone());

    // ---------- Start the audit ledger subscriber ----------
    // Deferred from the NATS-connect block above so it can be handed the
    // SecretsManager for the KEK-backed OTLP auth-header envelope (v3). If it
    // fails we want to know why, so propagate the error.
    if let Some(nats) = &nats_client {
        tracing::info!("Calling start_audit_ledger_subscriber");
        crate::audit_ledger::start_audit_ledger_subscriber(
            (**nats).clone(),
            db_pool.clone(),
            Some(secrets_manager.clone()),
        )
        .await?;
        tracing::info!("AUDIT_SUBSCRIBER_STARTED_AND_RUNNING");
    }

    // ---------- Wire actor_memory at-rest encryption ----------
    // Register the crypto hook BEFORE any memory writes. talos_memory
    // writers (Phase B) require the hook — writes panic-loud if it's
    // missing. See docs/security/agent-memory-encryption-plan.md.
    talos_memory::register_memory_crypto_hook(std::sync::Arc::new(
        crate::memory_crypto::SecretsManagerMemoryCrypto::new(secrets_manager.clone()),
    ));
    tracing::info!("actor_memory at-rest encryption hook registered");

    Ok(())
}

/// The integration / auth / OAuth / webhook service pile, the metrics
/// service, and the embedding-provider boot probe — in the exact
/// construction order of the pre-decomposition `main()` body.
async fn build_platform_services(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    redis_client: Option<std::sync::Arc<redis::Client>>,
    nats_client: Option<std::sync::Arc<async_nats::Client>>,
    buses: &EventBuses,
    core: &CoreServices,
) -> anyhow::Result<PlatformServices> {
    let secrets_manager = core.secrets_manager.clone();
    let registry = core.registry.clone();
    let tx = buses.tx.clone();
    let dlq_tx = buses.dlq_tx.clone();
    // ---------- Load worker shared key (for signing NATS job requests) ----------
    // Optional: if not set, Google Calendar webhook dispatch is disabled.
    // In production this MUST be set to the same value as the worker's WORKER_SHARED_KEY.
    let worker_shared_key: Option<talos_workflow_engine_core::WorkerSharedKey> =
        match talos_workflow_job_protocol::load_worker_shared_key() {
            Ok(key) => {
                tracing::info!("WORKER_SHARED_KEY loaded — calendar webhook dispatch enabled");
                Some(key)
            }
            Err(e) => {
                tracing::warn!(
                    "WORKER_SHARED_KEY not available: {}. \
                     Google Calendar webhook job dispatch will be disabled.",
                    e
                );
                None
            }
        };

    // ---------- Initialize WorkerManager (tracks live worker heartbeats) ----------
    // Uses the same shared key as the worker so heartbeat HMAC signatures can be verified.
    // An empty key is safe here: WorkerManager only gates scheduling health warnings, not auth.
    let worker_manager = std::sync::Arc::new(crate::worker_manager::WorkerManager::new(
        worker_shared_key
            .as_ref()
            .map(|k| k.as_ref().to_vec())
            .unwrap_or_default(),
    ));

    // ---------- Initialize DLP service ----------
    let dlp_service = std::sync::Arc::new(dlp::DlpService::from_env());

    // ---------- Initialize module execution service for logging ----------
    let module_execution_service = std::sync::Arc::new(
        ModuleExecutionService::new(db_pool.clone(), dlp_service.clone())
            .with_encryption(secrets_manager.clone()),
    );
    tracing::info!("Module execution service initialized (payload encryption enabled)");

    // ---------- Initialize unified OAuth credential service ----------
    // Created early so it can be passed into all integration services that do
    // dual-write token storage (Gmail, Google Calendar).
    let oauth_credential_service = std::sync::Arc::new(oauth::OAuthCredentialService::new(
        db_pool.clone(),
        secrets_manager.clone(),
    ));
    tracing::info!("OAuth credential service initialized");

    // ---------- Initialize Slack API client ----------
    let slack_api_client = std::sync::Arc::new(slack::SlackApiClient::new());
    tracing::info!("Slack API client initialized");

    // ---------- Initialize Slack integration service ----------
    let slack_integration_service = std::sync::Arc::new(
        slack::SlackIntegrationService::new(db_pool.clone())
            .map_err(|e| anyhow::anyhow!("Failed to initialize Slack integration service: {}", e))?
            .with_secrets_manager(secrets_manager.clone())
            .with_credentials_service(oauth_credential_service.clone()),
    );
    tracing::info!(
        "Slack integration service initialized (token encryption + credential service enabled)"
    );

    // ---------- Initialize Gmail integration service ----------
    let gmail_integration_service = std::sync::Arc::new(
        gmail::GmailIntegrationService::new(db_pool.clone())
            .map_err(|e| anyhow::anyhow!("Failed to initialize Gmail integration service: {}", e))?
            .with_secrets_manager(secrets_manager.clone())
            .with_credentials_service(oauth_credential_service.clone()),
    );
    tracing::info!("Gmail integration service initialized (token encryption + dual-write enabled)");

    // ---------- Initialize Google Cloud integration service ----------
    let google_cloud_integration_service = std::sync::Arc::new(
        google_cloud::GoogleCloudIntegrationService::new(db_pool.clone())
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to initialize Google Cloud integration service: {}",
                    e
                )
            })?
            .with_secrets_manager(secrets_manager.clone())
            .with_credentials_service(oauth_credential_service.clone()),
    );
    tracing::info!(
        "Google Cloud integration service initialized (token encryption + dual-write enabled)"
    );

    // Write-tier (Phase C provisioning) sibling: same OAuth client, separate
    // consent under provider "google_cloud_write" with scope-narrowed
    // pubsub+monitoring grants. See GcpTier docs in talos-google-cloud.
    let google_cloud_write_service = std::sync::Arc::new(
        google_cloud::GoogleCloudIntegrationService::new_write(db_pool.clone())
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to initialize Google Cloud write-tier service: {}",
                    e
                )
            })?
            .with_secrets_manager(secrets_manager.clone())
            .with_credentials_service(oauth_credential_service.clone()),
    );

    // Full-tier (Phase D impersonation base) sibling: broad cloud-platform
    // consent, host-reserved tokens, used only to mint impersonated SA tokens.
    let google_cloud_full_service = std::sync::Arc::new(
        google_cloud::GoogleCloudIntegrationService::new_full(db_pool.clone())
            .map_err(|e| {
                anyhow::anyhow!("Failed to initialize Google Cloud full-tier service: {}", e)
            })?
            .with_secrets_manager(secrets_manager.clone())
            .with_credentials_service(oauth_credential_service.clone()),
    );

    // Phase D: inject the impersonation-token provider into the secrets
    // resolver so `gcp/impersonated/<sa>/access_token` module paths mint at
    // dispatch. Set-once global, same pattern as the GitHub App provider.
    talos_oauth::resolver::set_gcp_impersonation_token_provider(std::sync::Arc::new(
        google_cloud::GcpImpersonationService::new(
            db_pool.clone(),
            google_cloud_full_service.clone(),
        ),
    ));

    // ---------- GitHub App connect service (RFC 0008 Phase B) ----------
    // Optional: enabled only when GITHUB_APP_ID (+ companions) are set. A
    // half-configured App (id set but a required field missing/blank, or an
    // unparseable key) fails loudly here so the controller doesn't silently boot
    // with a broken connect flow.
    let github_app_config = talos_github::GithubAppConfig::from_env()
        .map_err(|e| anyhow::anyhow!("Invalid GitHub App configuration: {}", e))?;
    if github_app_config.is_some() {
        tracing::info!("GitHub App connect flow enabled (RFC 0008)");
    }
    // B4-wiring: inject the App installation-token provider into the engine's
    // secret resolver so a module secret path `github_app:<owner>` resolves to a
    // minted installation token. Set-once global; no-op when the App is disabled.
    let github_token_resolver = std::sync::Arc::new(
        talos_github_connect::GithubTokenResolver::new(db_pool.clone(), github_app_config.clone()),
    );
    talos_oauth::resolver::set_github_installation_token_provider(github_token_resolver);
    let github_connect_service = std::sync::Arc::new(
        talos_github_connect::GithubConnectService::new(db_pool.clone(), github_app_config),
    );

    // ---------- Gmail push-notification (watch) service ----------
    // Optional. Requires an operator-created Pub/Sub topic + push
    // subscription. If GMAIL_PUBSUB_TOPIC is unset, push receiving
    // is disabled (the REST watch-channel routes still exist but
    // users.watch calls will fail at Google's API). See
    // docs/gmail-push-setup.md for the operator runbook.
    // MCP-710 (2026-05-13): empty-env class — see GmailIntegrationService.
    // `GMAIL_PUBSUB_TOPIC=""` (helm placeholder) would yield `Some("")`,
    // causing the GmailWatchService to be constructed with empty topic
    // and the warn line at ~599 ("Gmail push service disabled — set
    // GMAIL_PUBSUB_TOPIC to enable") never fires. Same story for
    // `GMAIL_PUBSUB_AUDIENCE` (verifier built with `aud=""`, all pushes
    // rejected, missing-audience warn never fires). `GMAIL_PUBSUB_SERVICE_ACCOUNT`
    // uses `unwrap_or_else` which doesn't fire on `Ok("")`, so an empty
    // env shadows the documented `gmail-api-push@system.gserviceaccount.com`
    // default and every push rejects with WrongEmail.
    let gmail_pubsub_topic = std::env::var("GMAIL_PUBSUB_TOPIC")
        .ok()
        .filter(|v| !v.is_empty());
    let gmail_pubsub_audience = std::env::var("GMAIL_PUBSUB_AUDIENCE")
        .ok()
        .filter(|v| !v.is_empty());
    let gmail_pubsub_service_account = std::env::var("GMAIL_PUBSUB_SERVICE_ACCOUNT")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "gmail-api-push@system.gserviceaccount.com".to_string());
    let gmail_default_labels: Vec<String> = std::env::var("GMAIL_DEFAULT_LABEL_IDS")
        .unwrap_or_else(|_| "INBOX".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let gmail_watch_service: Option<std::sync::Arc<gmail::watch::GmailWatchService>> =
        match &gmail_pubsub_topic {
            Some(topic) => {
                tracing::info!(%topic, "Gmail push service enabled");
                Some(std::sync::Arc::new(gmail::watch::GmailWatchService::new(
                    db_pool.clone(),
                    gmail_integration_service.clone(),
                    topic.clone(),
                    gmail_default_labels,
                )))
            }
            None => {
                tracing::info!("Gmail push service disabled (set GMAIL_PUBSUB_TOPIC to enable)");
                None
            }
        };

    let gmail_pubsub_verifier: Option<std::sync::Arc<gmail::pubsub_jwt::PubsubJwtVerifier>> =
        match (&gmail_watch_service, &gmail_pubsub_audience) {
            (Some(_), Some(aud)) => Some(std::sync::Arc::new(
                gmail::pubsub_jwt::PubsubJwtVerifier::new(
                    aud.clone(),
                    gmail_pubsub_service_account.clone(),
                ),
            )),
            (Some(_), None) => {
                tracing::warn!(
                    "GMAIL_PUBSUB_TOPIC is set but GMAIL_PUBSUB_AUDIENCE is not — \
                     Pub/Sub push endpoint will reject every delivery. Set the \
                     audience to match your Pub/Sub subscription's --push-auth-token-audience."
                );
                None
            }
            _ => None,
        };

    // ---------- Google Cloud push-notification (watch) service ----------
    // Optional. Enabled only when GCP_PUBSUB_AUDIENCE is set (the
    // subscription's --push-auth-token-audience). Unlike Gmail there is
    // NO topic/service-account env: the user creates the Pub/Sub
    // subscription + service account themselves and each watch row
    // carries its own expected service-account email. See
    // docs/gcp-push-setup.md. MCP-710 empty-env class: a helm-placeholder
    // "" reads as unset (all pushes would reject with an empty audience,
    // and the disabled-log would never fire).
    let gcp_pubsub_audience = std::env::var("GCP_PUBSUB_AUDIENCE")
        .ok()
        .filter(|v| !v.is_empty());
    let (gcp_watch_service, gcp_pubsub_verifier): (
        Option<std::sync::Arc<google_cloud::watch::GcpWatchService>>,
        Option<std::sync::Arc<talos_integration_helpers::google_jwt::GoogleOidcVerifier>>,
    ) = match &gcp_pubsub_audience {
        Some(_) => {
            tracing::info!("Google Cloud push service enabled");
            let watch = std::sync::Arc::new(google_cloud::watch::GcpWatchService::new(
                db_pool.clone(),
                google_cloud_integration_service.clone(),
            ));
            // The shared verifier holds only the JWK cache; the audience
            // is passed per-call and the service-account email is
            // per-watch, so one verifier serves every GCP watch channel.
            let verifier = std::sync::Arc::new(
                talos_integration_helpers::google_jwt::GoogleOidcVerifier::new(),
            );
            (Some(watch), Some(verifier))
        }
        None => {
            tracing::info!(
                "Google Cloud push service disabled (set GCP_PUBSUB_AUDIENCE to enable)"
            );
            (None, None)
        }
    };

    // ---------- Initialize Atlassian (Jira) integration service ----------
    let atlassian_integration_service = std::sync::Arc::new(
        atlassian::AtlassianIntegrationService::new(db_pool.clone())
            .map_err(|e| {
                anyhow::anyhow!("Failed to initialize Atlassian integration service: {}", e)
            })?
            .with_credentials_service(oauth_credential_service.clone()),
    );
    tracing::info!("Atlassian integration service initialized");

    // ---------- Initialize Gmail API client ----------
    let gmail_api_client = std::sync::Arc::new(gmail::GmailApiClient::new());
    tracing::info!("Gmail API client initialized");

    // ---------- Initialize Google Calendar integration service ----------
    // SecretsManager is required (not the per-call fresh instance we used
    // pre-r233) so OAuth-token DEK unwrap uses the shared, KEK-correct
    // manager. See `GoogleCalendarService::secrets_manager` docstring.
    let google_calendar_service = std::sync::Arc::new(google_calendar::GoogleCalendarService::new(
        db_pool.clone(),
        secrets_manager.clone(),
    ));
    if google_calendar_service.is_configured() {
        tracing::info!("Google Calendar integration service initialized");
    } else {
        tracing::warn!(
            "Google Calendar integration not configured (missing GOOGLE_CLIENT_ID/SECRET)"
        );
    }
    // Wire in the unified credential service for dual-write token storage.
    google_calendar_service.with_credentials_service(oauth_credential_service.clone());
    // Wire in the worker shared HMAC key for webhook-token signing. If
    // the key isn't set, watch-channel creation will fail closed —
    // safer than issuing channels Google will send to but we can't
    // verify on arrival. Empty / short keys are rejected up-front.
    if let Some(ref key) = worker_shared_key {
        if let Err(e) = google_calendar_service.with_worker_shared_key(key.as_bytes().to_vec()) {
            tracing::error!(error = %e, "gcal webhook HMAC key rejected; aborting");
            return Err(e);
        }
    }

    // ---------- Initialize Webhook Deduplication ----------
    let webhook_deduplication = redis_client.clone().map(|redis| {
        std::sync::Arc::new(idempotency::WebhookDeduplication::new(
            redis,
            std::time::Duration::from_secs(3600), // 1 hour dedup window
        ))
    });
    tracing::info!(
        "Webhook deduplication initialized: {}",
        webhook_deduplication.is_some()
    );

    // RFC 0010 P3 (M4): resolve the process-wide claim-based-sealing handle
    // ONCE and share it across the three module-bound (fire-and-forget)
    // dispatch paths — webhooks (below), Gmail push, Google-Calendar push.
    // `Some` only when TALOS_ENVELOPE_SEALING is audit/required AND an Ed25519
    // controller signing key is configured; those paths then register plaintext
    // for a worker claim instead of shipping a WSK envelope the worker refuses
    // under `required`. Resolving here (eagerly, at boot) starts the shared
    // claim responder + orphan-seal sweep before the first push arrives. Bridged
    // from the engine-NATS `EnvelopeSealingHandle` into the decoupled
    // `ModuleSealingHandle` the integration crates depend on.
    let module_sealing_handle: Option<talos_integration_helpers::ModuleSealingHandle> = nats_client
        .as_ref()
        .and_then(talos_engine::nats_run::shared_envelope_sealing_handle);

    // ---------- Initialize webhook router ----------
    // NOTE: Slack enrichment (user profiles, channel info, etc.) now happens inside
    // the slack-webhook-listener WASM template, not here in the controller.
    let circuit_breaker = std::sync::Arc::new(crate::webhooks::CircuitBreaker::new());
    let webhook_router = std::sync::Arc::new(WebhookRouter::new(
        db_pool.clone(),
        registry.clone(),
        secrets_manager.clone(),
        nats_client.clone().ok_or_else(|| {
            anyhow::anyhow!("NATS_URL must be configured for the new WebhookRouter architecture")
        })?,
        worker_shared_key.clone(),
        circuit_breaker.clone(),
        Some(worker_manager.clone()),
        Some(module_execution_service.clone()),
        tx.clone(),
        dlq_tx.clone(),
        webhook_deduplication.clone(),
        module_sealing_handle.clone(),
    )?);

    // ---------- Initialize authentication service ----------
    // Supports direct env var or Docker secrets file via JWT_SECRET_FILE
    let jwt_secret = crate::config::read_env_or_file("JWT_SECRET").ok_or_else(|| {
        anyhow::anyhow!(
            "JWT_SECRET environment variable must be set (generate with: openssl rand -hex 32)"
        )
    })?;

    // Validate JWT secret is not the old default value
    if jwt_secret == "dev_secret_change_in_production" || jwt_secret.len() < 32 {
        return Err(anyhow::anyhow!(
            "JWT_SECRET must be at least 32 characters and not use default value. Generate with: openssl rand -hex 32"
        ));
    }
    // Require sufficient entropy: at least 10 distinct characters
    let distinct_chars = jwt_secret
        .chars()
        .collect::<std::collections::HashSet<_>>()
        .len();
    if distinct_chars < 10 {
        return Err(anyhow::anyhow!(
            "JWT_SECRET must contain at least 10 distinct characters. Generate with: openssl rand -hex 32"
        ));
    }

    // Read bcrypt cost from environment (default to 12, which is the recommended production value)
    //
    // MCP-1077 (2026-05-16): enforce bcrypt's hard range [4, 31] at
    // startup so misconfigurations fail-closed at boot, not silently
    // on every login attempt. Pre-fix the error message promised
    // "between 10 and 14" but the code only checked u32 parse — values
    // like `BCRYPT_COST=3` or `=32` (outside bcrypt's actual valid
    // range) parsed cleanly, got handed to AuthService, then EVERY
    // login attempt failed with bcrypt's opaque `CostNotAllowed`
    // error → auth outage with the only signal a per-request error.
    // `=0` (the canonical Helm-placeholder footgun, see MCP-1063) also
    // parses fine and hits the same trap. Sibling defense-in-depth to
    // the `talos-config-validator` startup advisory which already
    // WARNs on values outside [10, 14] (recommended range) but does
    // NOT fail-closed on values outside bcrypt's actual range.
    let bcrypt_cost: u32 = std::env::var("BCRYPT_COST")
        .unwrap_or_else(|_| "12".to_string())
        .parse::<u32>()
        .map_err(|_| {
            anyhow::anyhow!(
                "BCRYPT_COST must be a valid number between 4 and 31 (recommended 10-14)"
            )
        })?;
    if !(4..=31).contains(&bcrypt_cost) {
        return Err(anyhow::anyhow!(
            "BCRYPT_COST={} is outside bcrypt's valid range [4, 31] — every login would fail. \
             Recommended production value: 12 (default).",
            bcrypt_cost
        ));
    }
    if !(10..=14).contains(&bcrypt_cost) {
        tracing::warn!(
            target: "talos_audit",
            event_kind = "bcrypt_cost_outside_recommended",
            bcrypt_cost,
            "BCRYPT_COST={} is outside the recommended range [10, 14]. \
             Below 10 is too weak for production; above 14 may produce login timeouts.",
            bcrypt_cost
        );
    }

    let auth_service = std::sync::Arc::new(
        AuthService::new(
            db_pool.clone(),
            jwt_secret,
            bcrypt_cost,
            redis_client.clone(),
        )
        .map_err(|e| anyhow::anyhow!("Failed to initialize auth service: {}", e))?,
    );
    tracing::info!("Auth service initialized with bcrypt cost: {}", bcrypt_cost);

    // MCP-1078 (2026-05-16): validate ADMIN_SECRET_KEY at startup
    // when admin ops are enabled. Pre-fix the three admin gates
    // (talos-gmail, talos-google-calendar, controller secrets-admin)
    // checked `admin_secret.is_empty()` at REQUEST time (fail-closed
    // for unset) but had NO strength validation. An operator who set
    // `ENABLE_ADMIN_OPS=true` + `ADMIN_SECRET_KEY=x` (single char)
    // got a working admin gate where one-character guessing wins —
    // a critical auth weakness with no operator signal.
    //
    // Sibling fail-closed-at-boot class to MCP-1066 (CSRF bypass
    // guard) and MCP-1077 (bcrypt cost range). When admin ops are
    // disabled (default), ADMIN_SECRET_KEY is not read and no
    // validation applies — operator-friendly for non-admin
    // deployments.
    //
    // Minimum: 32 chars matching JWT_SECRET's threshold. The admin
    // gate runs the same constant-time compare as session auth, so
    // the entropy bar should match. Doesn't enforce distinct-chars
    // (JWT secret check) since `openssl rand -hex 32` produces 16
    // distinct hex chars max — keeping the rule to a single
    // length-based threshold.
    // MCP-1081 (2026-05-16): routed through canonical
    // `talos_config::validate_shared_secret_token` so the three
    // shared-secret tokens (admin / metrics / registry-publish) share
    // one validator with consistent error messaging.
    if talos_config::admin_ops_enabled() {
        talos_config::validate_shared_secret_token(
            "ADMIN_SECRET_KEY",
            32,
            true,
            "Leaving ADMIN_SECRET_KEY weak when admin ops are enabled is a critical auth weakness — \
             admin endpoints would accept trivially-guessable secrets.",
        ).map_err(|e| anyhow::anyhow!("ENABLE_ADMIN_OPS is set but {}", e))?;
        tracing::warn!(
            target: "talos_audit",
            event_kind = "admin_ops_enabled",
            "ENABLE_ADMIN_OPS=true at startup: admin endpoints are reachable with X-Admin-Secret. \
             Production deployments should leave this unset; admin operations should run via the \
             standard authenticated MCP / GraphQL surface instead."
        );
    }

    // MCP-1079/1081: PROMETHEUS_SCRAPE_TOKEN strength via canonical validator.
    talos_config::validate_shared_secret_token(
        "PROMETHEUS_SCRAPE_TOKEN",
        32,
        false,
        "The scrape endpoint exposes the full Prometheus metrics registry — a \
         trivially-guessable token gives attackers cross-tenant metrics access.",
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    // MCP-1080/1081: REGISTRY_PUBLISH_TOKEN strength via canonical validator.
    talos_config::validate_shared_secret_token(
        "REGISTRY_PUBLISH_TOKEN",
        32,
        false,
        "The publish endpoint accepts module template artifacts distributed across the fleet — \
         a trivially-guessable token gives attackers arbitrary template injection capability.",
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    // ---------- Initialize TOTP/2FA service ----------
    let totp_service = std::sync::Arc::new(totp_2fa::TotpService::new(
        db_pool.clone(),
        redis_client.clone(),
        secrets_manager.clone(),
    ));
    tracing::info!("TOTP/2FA service initialized");

    // ---------- Initialize API key service ----------
    let api_key_service = std::sync::Arc::new(api_keys::ApiKeyService::new(
        db_pool.clone(),
        redis_client.clone(),
    ));
    tracing::info!("API key service initialized");

    // ---------- Initialize OAuth service ----------
    let oauth_service = std::sync::Arc::new(
        OAuthService::new(db_pool.clone(), redis_client.clone())
            .map_err(|e| anyhow::anyhow!("Failed to initialize OAuth service: {}", e))?,
    );
    tracing::info!("OAuth service initialized");

    // MCP-706 (2026-05-13): same operator-trust class as MCP-704 / MCP-705.
    // TWO more dead-binding boot scaffolds removed here, both with material
    // production implications — naming them so a future operator searching
    // the codebase for "distributed rate limit" / "circuit breaker" gets
    // ground truth instead of silence:
    //
    // 1. `circuit_breaker::CircuitBreakerRegistry::new()` (was bound to
    //    `circuit_breakers`) — Redis, NATS, and Database breakers were
    //    pre-registered but nothing ever called
    //    `with_circuit_breaker(registry.get("redis").await.unwrap(), op)`
    //    around the actual Redis / NATS / sqlx calls. The registry sat
    //    inert while the rest of the controller continued to make raw
    //    Redis/NATS/DB calls, so under an upstream outage requests pile
    //    up at the driver layer per individual timeout — no fail-fast,
    //    no half-open recovery probe, no operator-visible state
    //    transition. The "Circuit breaker registry initialized" log
    //    line was the lie.
    //    The `talos-circuit-breaker` crate itself works correctly
    //    (MCP-446 fixed `Clone` to share `Arc<RwLock<_>>` state; MCP-485
    //    fixed a lock-order deadlock; tests pass), but wiring it into
    //    the real call sites is a separate effort.
    //    The `webhooks::CircuitBreaker` instance allocated above (line
    //    ~680) is a DIFFERENT, narrower breaker that IS consumed via
    //    `WebhookRouter::new(..., circuit_breaker.clone(), ...)` and
    //    actively protects per-trigger webhook delivery — leave that
    //    alone.
    //
    // 2. `distributed_ratelimit::DistributedRateLimiter::new(redis,
    //    RateLimitConfig::api())` — bound to `distributed_rate_limiter`
    //    inside an `Option`, never consumed. The "Distributed rate
    //    limiter initialized: true/false" log line read the
    //    `is_some()` of the dead Option for its boolean. Production
    //    impact: API rate-limiting falls back to the in-memory
    //    per-replica limiter (`api_limiter` at line ~1110 — `governor`-
    //    backed `RateLimiter` Extension consumed by every public
    //    route), so an attacker hitting N replicas behind a load
    //    balancer gets N× the effective rate. The auth-rate-limiter
    //    (`auth_rate_limiter` below) IS the real distributed limiter
    //    and IS consumed (passed into the GraphQL schema via `.data()`
    //    so login attempts ARE coordinated across replicas) —
    //    THAT one stays.
    //
    //    Mitigations operators should know about given the gap:
    //    * The per-IP `extract_client_ip` walk (RFC 7239 right-to-left,
    //      memory entry `rate_limit_pattern`) IS correct and rejects
    //      X-Forwarded-For spoofing, so the per-replica limit still
    //      gates each real client correctly.
    //    * `global_limiter` (line ~1124) caps total RPS per replica so
    //      a single replica can't be overwhelmed.
    //    * Helm replica count × per-replica RPS is the effective
    //      ceiling. Currently default 1 replica → no gap. With
    //      replicas > 1 the gap opens.
    //
    // Workspace crates + shim files left intact so wiring up either
    // service later doesn't need re-import.

    // Auth-specific rate limiter: uses auto() which is fail-closed in production
    // (rejects requests when Redis is unavailable) to prevent distributed brute-force.
    let auth_rate_limiter = std::sync::Arc::new(rate_limit::DistributedRateLimiter::auto(
        redis_client.clone(),
        rate_limit::RateLimitConfig::auth(),
        "auth",
    ));
    tracing::info!(
        "Auth rate limiter initialized (policy: {})",
        if config::is_production() {
            "fail-closed"
        } else {
            "fail-open"
        }
    );

    // MCP-705 (2026-05-13): same operator-trust class as MCP-704.
    // `feature_flags::FeatureFlagService::new(db_pool)` was bound to
    // `_feature_flags`, never used. Even if it WERE wired up,
    // `is_enabled` would return `Ok(false)` for every call because
    // `load_flag` is a `// Placeholder - would query database; Ok(None)`
    // stub — no migration shipped, no DB layer implemented. Operators
    // and future developers seeing "Feature flags service initialized"
    // would assume a working rollout system; in reality every
    // percentage / user-list / tenant-list flag evaluation collapses to
    // false. Higher-stakes than the MCP-704 four because a future
    // gate-on-flag callsite would silently disable the feature it's
    // supposed to gradually roll out. Removed the boot line; workspace
    // crate + 3-LoC shim left intact so a real implementation can land
    // later without re-import churn.

    // ---------- Initialize Idempotency Service ----------
    let idempotency_service = redis_client.clone().map(|redis| {
        std::sync::Arc::new(idempotency::IdempotencyService::new(
            redis,
            std::time::Duration::from_secs(86400), // 24 hour TTL
        ))
    });
    tracing::info!(
        "Idempotency service initialized: {}",
        idempotency_service.is_some()
    );

    // MCP-704 (2026-05-13): removed four dead-binding boot-time scaffolds
    // that mis-led operators via `tracing::info!("X initialized")` lines
    // for services that were never wired into app state / Extensions /
    // background loops:
    //
    // - `tenancy::TenantIsolation::new()` — bound to `_tenant_isolation`,
    //   never used; tenant isolation is actually enforced at the
    //   repository layer (per-user / per-org SQL gates).
    // - `secrets_rotation::SecretsRotation::new()` — bound to
    //   `_secrets_rotation`, never used; the in-memory `KeyVersion`
    //   tracker never persisted anywhere. The log line "Secrets rotation
    //   manager initialized" was the highest-priority lie: an operator
    //   relying on it would believe automatic JWT/DEK rotation is active
    //   when actual rotation lives in `SecretsManager::rotate_master_key`
    //   / `rotate_dek` and runs ONLY when invoked manually.
    // - `jobs::JobQueue::new(db_pool.clone(), 10)` — bound to
    //   `__job_queue`, never used; the crate's persistence layer was
    //   never exercised because no caller pushed jobs.
    // - `db_monitor::QueryMonitor::new()` — bound to `_query_monitor`,
    //   never used; no callsite recorded queries.
    //
    // Workspace crates + 3-LoC shim files kept in place so future wiring
    // doesn't have to re-import; only the misleading boot allocations +
    // log lines removed. Same "operator-facing log lies about what's
    // running" class as the embedding-provider probe (r239 / r241) where
    // an env-var-only check was upgraded to a real round-trip probe.

    // ---------- Initialize Metrics Service ----------
    let metrics = metrics::TalosMetrics::new()
        .map_err(|e| anyhow::anyhow!("Failed to initialize metrics: {}", e))?;
    metrics::set_global(metrics.clone());
    tracing::info!("Metrics service initialized");

    // ---------- Embedding-provider boot probe (added r239) ----------
    //
    // Surface a missing/misconfigured embedding provider at startup instead
    // of letting it silently bite the per-session auto-heal path.
    //
    // r241: replaced the syntactic env-var check with a real round-trip probe
    // (caught the false-positive where EMBEDDING_API_URL was set to a phantom
    // in-cluster ollama URL — passed `from_env().is_some()` but every embed
    // request failed at the network layer). The probe runs once at boot and
    // every PROVIDER_PROBE_INTERVAL (5 min) via the background task below.
    //
    // We `await` the boot probe so session_start callers see ground truth
    // immediately, not "not yet probed". Cost: ~200ms one-time. If the probe
    // fails, the server still boots — the WARN gives operators an actionable
    // line, and the background refresh will pick up provider recovery without
    // a restart.
    crate::mcp::search::refresh_embedding_provider_health().await;
    let (avail, last_err) = crate::mcp::search::embedding_provider_status();
    if avail {
        tracing::info!("Embedding provider probe succeeded");
    } else {
        tracing::warn!(
            error = ?last_err,
            "Embedding provider probe FAILED — semantic_search will fall back to \
             trigram/ILIKE and session_start auto-embedding will no-op until \
             this is fixed. Set EMBEDDING_API_KEY (or OPENAI_API_KEY) for hosted, \
             OR EMBEDDING_API_URL pointing at a reachable OpenAI-compatible \
             endpoint. Helm: populate EMBEDDING_* keys in the bootstrap secret \
             (see scripts/patch-bootstrap-secret.sh)."
        );
    }

    Ok(PlatformServices {
        worker_shared_key,
        worker_manager,
        dlp_service,
        module_execution_service,
        oauth_credential_service,
        slack_api_client,
        slack_integration_service,
        gmail_integration_service,
        google_cloud_integration_service,
        google_cloud_write_service,
        google_cloud_full_service,
        github_connect_service,
        gmail_watch_service,
        gmail_pubsub_verifier,
        gcp_watch_service,
        gcp_pubsub_verifier,
        gcp_pubsub_audience,
        atlassian_integration_service,
        gmail_api_client,
        google_calendar_service,
        circuit_breaker,
        webhook_router,
        auth_service,
        totp_service,
        api_key_service,
        oauth_service,
        auth_rate_limiter,
        idempotency_service,
    })
}

/// Embedding-provider re-probe loop + crypto-invariant orphan gauges +
/// DB-pool saturation gauges. Extracted verbatim from `main()`; spawn order
/// preserved.
fn spawn_metrics_gauge_tasks(db_pool: sqlx::Pool<sqlx::Postgres>) {
    // Background refresh — every 5 min, re-probe the provider so that
    // operator config rotations (key swap, URL change, tier upgrade) are
    // picked up without a controller restart. The interval is intentionally
    // long: even Voyage's free 3 RPM tier loses just ~6% of capacity to
    // these probes.
    tokio::spawn(async {
        let mut ticker = tokio::time::interval(crate::mcp::search::PROVIDER_PROBE_INTERVAL);
        // First tick fires immediately — skip it so we don't double-probe at boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            crate::mcp::search::refresh_embedding_provider_health().await;
        }
    });

    // Background task: crypto-invariant orphan counts. Runs every 60s
    // and updates three gauges the alerts in
    // deploy/observability/alerts.yaml page on. A value > 0 for any of
    // them means at-rest encrypted data is unrecoverable — the same
    // failure mode that silently bit us on 2026-04-24 before Vault
    // persistence was wired up. See docs/security/operational-runbook.md.
    {
        let pool = db_pool.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            // First tick fires immediately — skip it so startup isn't noisy.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Some(m) = metrics::global() {
                    // actor_memory
                    if let Ok(row) = sqlx::query_scalar::<_, i64>(
                        "SELECT COUNT(*) FROM actor_memory am \
                         WHERE NOT EXISTS ( \
                             SELECT 1 FROM encryption_keys ek WHERE ek.id = am.value_key_id \
                         )",
                    )
                    .fetch_one(&pool)
                    .await
                    {
                        m.actor_memory_orphaned_rows.set(row);
                    }
                    // module_executions (payload_enc_key_id is nullable)
                    if let Ok(row) = sqlx::query_scalar::<_, i64>(
                        "SELECT COUNT(*) FROM module_executions me \
                         WHERE me.payload_enc_key_id IS NOT NULL \
                           AND NOT EXISTS ( \
                             SELECT 1 FROM encryption_keys ek WHERE ek.id = me.payload_enc_key_id \
                         )",
                    )
                    .fetch_one(&pool)
                    .await
                    {
                        m.module_execution_orphaned_rows.set(row);
                    }
                    // workflow_executions
                    if let Ok(row) = sqlx::query_scalar::<_, i64>(
                        "SELECT COUNT(*) FROM workflow_executions we \
                         WHERE we.output_enc_key_id IS NOT NULL \
                           AND NOT EXISTS ( \
                             SELECT 1 FROM encryption_keys ek WHERE ek.id = we.output_enc_key_id \
                         )",
                    )
                    .fetch_one(&pool)
                    .await
                    {
                        m.workflow_execution_orphaned_rows.set(row);
                    }
                }
            }
        });
    }

    // Background task: Postgres connection-pool saturation gauges. Runs
    // every 15s and exports size / idle / in-use / max so the alert
    // `TalosDBPoolSaturated` (deploy/observability/alerts.yaml) can fire
    // before acquisitions start blocking on the 10s acquire timeout.
    // Pool state was previously un-instrumented — a saturated pool
    // surfaced only as climbing request latency with no direct signal.
    // The pool is process-local, so every controller replica samples its
    // own; the sum across replicas must stay below the backend's
    // server-side connection ceiling (see the per-subject RPC semaphore
    // note in docs/architecture/managed-cloud.md).
    {
        let pool = db_pool.clone();
        let max_connections: i64 = std::env::var("DB_MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(30);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(15));
            loop {
                ticker.tick().await;
                if let Some(m) = metrics::global() {
                    // `size()` is total connections (idle + in-use);
                    // `num_idle()` is the currently-available subset.
                    let size = i64::from(pool.size());
                    let idle = i64::try_from(pool.num_idle()).unwrap_or(i64::MAX);
                    m.db_pool_connections.set(size);
                    m.db_pool_idle_connections.set(idle);
                    m.db_pool_in_use_connections.set((size - idle).max(0));
                    m.db_pool_max_connections.set(max_connections);
                }
            }
        });
    }
}

/// OCI registry background sync loop. Extracted verbatim from `main()` —
/// must start AFTER `seed_templates` / `seed_marketplace`.
fn spawn_registry_sync(registry: std::sync::Arc<ModuleRegistry>) {
    // ---------- Start OCI Registry background sync loop ----------
    let sync_registry = registry.clone();
    tokio::spawn(async move {
        registry::sync::start_registry_sync_loop(sync_registry).await;
    });
}

/// LLM-keys/DEK cache sweeps, audit-chain verification sweep, bcrypt-cache
/// revocation sweep, and the modules-table reconciliation sweep. Extracted
/// verbatim from `main()`; spawn order preserved.
fn spawn_maintenance_sweeps(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    secrets_manager: std::sync::Arc<SecretsManager>,
    bg_shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    // ---------- Start LLM-keys cache sweep loop ----------
    //
    // The LLM-keys cache (`SecretsManager::llm_keys_cache`) evicts expired
    // entries lazily on read, which bounds memory for *active* users. A user
    // who makes one request and then goes silent leaves their entry in the
    // cache forever. This task sweeps expired entries on a fixed interval
    // so total cache size stays bounded under long-running multi-tenant
    // load with churning users.
    //
    // Interval defaults to 300s (5 min) and is bounded to [60s, 3600s] so
    // operators can tighten the sweep under high-churn workloads without
    // risk of a runaway tight loop. Emits a structured event per sweep so
    // operators can see how much is being evicted.
    let sweep_sm = secrets_manager.clone();
    let sweep_interval_secs: u64 = std::env::var("LLM_KEYS_SWEEP_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300)
        .clamp(60, 3600);
    let llm_sweep_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = llm_sweep_shutdown;
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(sweep_interval_secs));
        // Burn the immediate first tick so we don't sweep an empty cache at startup.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let evicted = sweep_sm.sweep_expired_llm_keys();
                    if evicted > 0 {
                        tracing::info!(
                            target: "talos_engine",
                            event_kind = "llm_keys_cache_sweep",
                            evicted,
                            interval_secs = sweep_interval_secs,
                            "swept expired LLM-keys cache entries"
                        );
                    }
                    // MCP-1093: piggyback on the same tick to bound the
                    // DEK cache's plaintext-AES-key memory residency.
                    // Same rationale as the LLM-keys sweep — `get_dek`
                    // evicts on read but historical DEK ids never
                    // re-queried after key rotation stay in the heap.
                    let dek_evicted = sweep_sm.sweep_expired_deks();
                    if dek_evicted > 0 {
                        tracing::info!(
                            target: "talos_engine",
                            event_kind = "dek_cache_sweep",
                            evicted = dek_evicted,
                            interval_secs = sweep_interval_secs,
                            "swept expired DEK cache entries"
                        );
                    }
                    // MCP-1133: sweep the single-slot `active_dek_cache`
                    // alongside the secondary cache. The MCP-1093 fix
                    // missed this slot — low-traffic deploys post-key-
                    // rotation leave the old active-DEK plaintext in
                    // the heap until the next active-DEK request.
                    if sweep_sm.sweep_expired_active_dek().await {
                        tracing::info!(
                            target: "talos_engine",
                            event_kind = "active_dek_cache_sweep",
                            interval_secs = sweep_interval_secs,
                            "swept expired active-DEK cache entry"
                        );
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("LLM-keys cache sweep loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });

    // ---------- Self-monitoring bridge: execution failures → ops_alerts ----------
    //
    // Cursor reconciler over terminal `workflow_executions` rows (see
    // `talos_ops_alerts_repository::self_monitor` for the design: why a
    // cursor beats finalizer hooks, the completed_at-vs-updated_at
    // choice, the safety lag, and the FOR UPDATE SKIP LOCKED
    // single-instance guard). Unattended failures become deduped
    // `source='talos'` ops alerts; a later green run auto-resolves
    // them. Kill switch TALOS_SELF_ALERTS=0; interval
    // TALOS_SELF_ALERTS_INTERVAL_SECS (default 60, clamped 5..=3600).
    if talos_ops_alerts_repository::self_monitor::self_alerts_enabled() {
        let self_monitor_pool = db_pool.clone();
        let self_monitor_shutdown = bg_shutdown_rx.clone();
        // Canonical env parsing (warns on non-positive garbage instead
        // of silently substituting — the zero-env-var footgun class).
        let self_monitor_interval: u64 = talos_config::positive_env_or_default(
            "TALOS_SELF_ALERTS_INTERVAL_SECS",
            talos_ops_alerts_repository::self_monitor::DEFAULT_TICK_INTERVAL_SECS,
        )
        .clamp(5, 3600);
        tokio::spawn(async move {
            let mut shutdown = self_monitor_shutdown;
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(self_monitor_interval));
            // Skip (not Burst, the default) missed ticks: after a
            // laptop sleep or long DB stall, ONE tick drains the whole
            // backlog internally — replaying ~60 queued ticks would
            // just hammer the cursor row with no-op transactions.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Burn the immediate first tick — nothing has finalized yet
            // this boot, and startup is busy enough.
            ticker.tick().await;
            tracing::info!(
                target: "talos_self_alerts",
                interval_secs = self_monitor_interval,
                "self-monitoring bridge reconciler started"
            );
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        talos_ops_alerts_repository::self_monitor::tick_and_log(
                            &self_monitor_pool,
                        )
                        .await;
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            tracing::info!("self-monitoring reconciler received shutdown signal");
                            break;
                        }
                    }
                }
            }
        });
    } else {
        tracing::info!(
            target: "talos_self_alerts",
            "self-monitoring bridge disabled via TALOS_SELF_ALERTS"
        );
    }

    // ---------- RFC 0010 P2 inc.4: dynamic worker-identity key refresh ---------
    //
    // Merges the DB-backed `worker_identities` registry into job_protocol's
    // dynamic verifying-key overlay (union with the static
    // `TALOS_WORKER_PUBLIC_KEYS` env base) so an autoscaling fleet can register
    // keys without an operator editing a ConfigMap. Verify-path reads are
    // lock-free (ArcSwap); this task just re-publishes the active set on an
    // interval, so max staleness for a rotation/revocation = one interval.
    //
    // Initial load is SYNCHRONOUS so DB-registered keys can verify the very first
    // job result after boot; a transient DB error there is non-fatal (env
    // registry stays live, the loop retries). `TALOS_WORKER_KEY_REFRESH_SECS=0`
    // disables the loop for deploys that use the env registry only.
    let worker_key_refresh_secs: u64 = std::env::var("TALOS_WORKER_KEY_REFRESH_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60);
    if worker_key_refresh_secs == 0 {
        tracing::info!(
            "Dynamic worker-identity key refresh disabled (TALOS_WORKER_KEY_REFRESH_SECS=0); \
             TALOS_WORKER_PUBLIC_KEYS env registry only"
        );
    } else {
        let refresh_secs = worker_key_refresh_secs.clamp(10, 3600);
        let worker_id_repo =
            talos_worker_identity_repository::WorkerIdentityRepository::new(db_pool.clone());
        let refresh_shutdown = bg_shutdown_rx.clone();
        tokio::spawn(async move {
            let mut shutdown = refresh_shutdown;
            // Immediate load so DB-registered keys go live shortly after boot; a
            // transient error here is non-fatal (env registry stays active, the
            // loop retries on the interval).
            match refresh_worker_key_overlay(&worker_id_repo).await {
                Ok(n) => tracing::info!(
                    target: "talos_engine",
                    event_kind = "worker_key_overlay_refresh",
                    installed = n,
                    "loaded dynamic worker-identity keys at boot"
                ),
                Err(e) => tracing::warn!(
                    target: "talos_engine",
                    error = %e,
                    "initial worker-identity key load failed; env registry still active, \
                     will retry on interval"
                ),
            }
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(refresh_secs));
            // Burn the immediate first tick — we just loaded above.
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Err(e) = refresh_worker_key_overlay(&worker_id_repo).await {
                            tracing::warn!(
                                target: "talos_engine",
                                error = %e,
                                "worker-identity key refresh failed; keeping last snapshot"
                            );
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            tracing::info!(
                                "worker-identity key refresh loop received shutdown signal"
                            );
                            break;
                        }
                    }
                }
            }
        });
    }

    // ---------- Audit-chain verification sweep (finding #2, Layer 2) ----------
    //
    // Continuously verifies the WORM audit ledger: each tick runs the offline
    // chain verifier over recently-completed executions and emits a loud
    // structured `audit_chain_verification_failed` event for any break
    // (tamper / deletion / reorder / bad HMAC). This is what turns "we CAN
    // verify the chain" into "we continuously DO" — the inline per-message
    // check (`talos_audit_ledger::verify_audit_message`) catches forgery at
    // ingest; this sweep catches gaps/deletions that only the full ordered
    // set reveals. Runs as a trusted system task on the bare pool (the audit
    // ledger is intentionally cross-tenant), so it needs no MCP/RBAC surface.
    //
    // Self-disables when no S3/WORM endpoint is configured (the from_env
    // helper returns None). Interval default 1h, clamped [300s, 86400s];
    // `AUDIT_CHAIN_SWEEP_INTERVAL_SECS=0` disables it. Lookback is 2× the
    // interval so window edges overlap (re-verification is idempotent); the
    // 120s settle floor skips just-finished executions whose audit events may
    // still be batching to S3, avoiding false sequence-gap reports.
    let audit_sweep_interval_secs: u64 = std::env::var("AUDIT_CHAIN_SWEEP_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3600);
    if audit_sweep_interval_secs == 0 {
        tracing::info!(
            "Audit-chain verification sweep disabled (AUDIT_CHAIN_SWEEP_INTERVAL_SECS=0)"
        );
    } else {
        let audit_sweep_interval_secs = audit_sweep_interval_secs.clamp(300, 86400);
        let audit_sweep_pool = db_pool.clone();
        let audit_sweep_shutdown = bg_shutdown_rx.clone();
        let lookback_secs = (audit_sweep_interval_secs as i64).saturating_mul(2);
        const SETTLE_SECS: i64 = 120;
        const MAX_EXECUTIONS_PER_SWEEP: i64 = 500;
        tokio::spawn(async move {
            let mut shutdown = audit_sweep_shutdown;
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(audit_sweep_interval_secs));
            // Burn the immediate first tick — at startup the most-recent
            // executions are still inside the settle window anyway.
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Some(stats) = talos_audit_ledger::run_chain_verification_sweep_from_env(
                            &audit_sweep_pool,
                            lookback_secs,
                            SETTLE_SECS,
                            MAX_EXECUTIONS_PER_SWEEP,
                        )
                        .await
                        {
                            if stats.failed > 0 || stats.errored > 0 {
                                tracing::warn!(
                                    target: "talos_audit",
                                    event_kind = "audit_chain_sweep_summary",
                                    scanned = stats.scanned,
                                    verified_ok = stats.verified_ok,
                                    failed = stats.failed,
                                    errored = stats.errored,
                                    "audit chain verification sweep completed WITH findings"
                                );
                            } else if stats.scanned > 0 {
                                tracing::info!(
                                    target: "talos_audit",
                                    event_kind = "audit_chain_sweep_summary",
                                    scanned = stats.scanned,
                                    verified_ok = stats.verified_ok,
                                    "audit chain verification sweep completed clean"
                                );
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            tracing::info!("Audit-chain verification sweep loop received shutdown signal");
                            break;
                        }
                    }
                }
            }
        });
    }

    // ---------- MCP-991: bcrypt cache revocation sweep ----------
    // Closes the residual revocation gap that the per-entry TTL can't
    // reach when `revoke_mcp_agent` deletes an `mcp_agents` row via
    // GraphQL. The cache lives in talos-mcp-handlers; talos-api can't
    // depend on it (workspace dep direction rule). The sweep runs
    // here at controller startup with the canonical db_pool — a
    // single batched query against ALL cached agent_ids drops the
    // revocation window from 10 s (TTL only) to ~3 s.
    crate::mcp::auth::spawn_bcrypt_cache_revocation_sweep(db_pool.clone(), bg_shutdown_rx.clone());

    // ---------- Phase 1.3 / Phase 5 residual reconciliation sweep ----------
    // Historical context: originally a dual-write safety net that mirrored
    // legacy table rows into the new `modules` table. Post-Phase-5 migration
    // all live write paths land directly in `modules` and the legacy tables
    // are frozen, so this sweep is a no-op in steady state — kept wired up
    // because the repository method is idempotent (ON CONFLICT DO NOTHING)
    // and it catches any stray residual row during the Phase 5 wind-down
    // window. Safe to remove after the legacy tables drop.
    {
        let recon_repo =
            std::sync::Arc::new(module_repository::ModuleRepository::new(db_pool.clone()));
        let recon_interval_secs: u64 = std::env::var("MODULES_RECONCILE_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(600)
            .clamp(60, 3600);
        // MCP-1042: subscribe to bg_shutdown_rx so SIGTERM exits the
        // sweep loop cleanly between ticks. Without this, an INSERT
        // statement issued mid-tick can wedge its connection-pool
        // entry on abort.
        let recon_shutdown = bg_shutdown_rx.clone();
        tokio::spawn(async move {
            let mut shutdown = recon_shutdown;
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(recon_interval_secs));
            // First tick fires immediately — sweep on startup so a fresh
            // boot picks up anything new without waiting one interval.
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        match recon_repo.reconcile_modules_table().await {
                            Ok((wasm_added, template_added)) => {
                                if wasm_added > 0 || template_added > 0 {
                                    tracing::info!(
                                        target: "talos_engine",
                                        event_kind = "modules_reconcile_sweep",
                                        wasm_added,
                                        template_added,
                                        interval_secs = recon_interval_secs,
                                        "mirrored legacy module rows into modules table"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    target: "talos_engine",
                                    error = %e,
                                    "modules-table reconciliation sweep failed"
                                );
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            tracing::info!(
                                target: "talos_engine",
                                "modules-table reconciliation sweep received shutdown signal"
                            );
                            break;
                        }
                    }
                }
            }
        });
        tracing::info!(
            target: "talos_engine",
            interval_secs = recon_interval_secs,
            "modules-table reconciliation sweep enabled"
        );
    }

    tracing::info!(
        "LLM-keys cache sweep loop started (interval: {}s)",
        sweep_interval_secs
    );
}

/// Per-IP / global rate limiters + IP whitelist + trusted-proxy list.
/// Extracted verbatim from `main()`.
fn build_rate_limiters() -> RateLimiters {
    // ---------- Initialize rate limiters ----------
    // Read rate limit configuration from environment variables
    // Load rate‑limit settings using the shared helper.
    let api_rate_limit = rate_limit::env_rate_limit("API_RATE_LIMIT", 100);
    let webhook_rate_limit = rate_limit::env_rate_limit("WEBHOOK_RATE_LIMIT", 60);
    let global_rate_limit = rate_limit::env_rate_limit("GLOBAL_RATE_LIMIT", 1000);

    // API rate limiter: configurable requests/min per IP (general GraphQL queries)
    let api_limiter = rate_limit::create_rate_limiter(rate_limit::RateLimitConfig {
        requests: api_rate_limit,
        per: std::time::Duration::from_secs(60),
        burst_size: (api_rate_limit / 5).max(10), // 20% of limit or min 10
    });

    // Webhook rate limiter: configurable requests/min per IP
    let webhook_limiter = rate_limit::create_rate_limiter(rate_limit::RateLimitConfig {
        requests: webhook_rate_limit,
        per: std::time::Duration::from_secs(60),
        burst_size: (webhook_rate_limit / 6).max(5), // ~17% of limit or min 5
    });

    // Global rate limiter: configurable requests/min total (prevents system overload)
    let global_limiter = rate_limit::create_global_rate_limiter(rate_limit::RateLimitConfig {
        requests: global_rate_limit,
        per: std::time::Duration::from_secs(60),
        burst_size: (global_rate_limit / 2).max(500), // 50% of limit or min 500 (was 10% - too restrictive!)
    });

    tracing::info!(
        "Rate limiters initialized - API: {}/min, Webhooks: {}/min, Global: {}/min",
        api_rate_limit,
        webhook_rate_limit,
        global_rate_limit
    );

    // ---------- Initialize IP whitelist for rate limiting ----------
    let whitelist = match std::env::var("TRUSTED_IPS") {
        Ok(whitelist_str) if !whitelist_str.is_empty() => {
            match rate_limit::IpWhitelist::from_string(&whitelist_str) {
                Ok(wl) => {
                    tracing::info!("IP whitelist configured: {}", whitelist_str);
                    std::sync::Arc::new(wl)
                }
                Err(e) => {
                    tracing::error!("Invalid TRUSTED_IPS format: {}", e);
                    std::sync::Arc::new(rate_limit::IpWhitelist::empty())
                }
            }
        }
        _ => {
            tracing::info!("No IP whitelist configured");
            std::sync::Arc::new(rate_limit::IpWhitelist::empty())
        }
    };

    // ---------- Initialize trusted proxy list for X-Forwarded-For ----------
    // Set TRUSTED_PROXY_CIDRS to your reverse proxy CIDR(s) so that real client
    // IPs are used for per-IP rate limiting when behind Nginx/Caddy/etc.
    // Example: TRUSTED_PROXY_CIDRS=172.16.0.0/12 (Docker bridge default)
    let trusted_proxies = std::sync::Arc::new(rate_limit::TrustedProxies::from_env());

    RateLimiters {
        api_rate_limit,
        webhook_rate_limit,
        global_rate_limit,
        api_limiter,
        webhook_limiter,
        global_limiter,
        whitelist,
        trusted_proxies,
    }
}

/// Cleanup / retention / archival sweeps (sessions, API keys, OAuth state
/// tokens, executions, audit logs, suspensions, WASM cache, webhook +
/// IP rate limiters, stuck executions), the one-shot crash-recovery resume
/// sweep (RFC 0003), the DEK cache cleanup, and the actor-memory TTL sweep.
/// Extracted verbatim from `main()`; spawn order preserved.
fn spawn_cleanup_tasks(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    nats_client: Option<std::sync::Arc<async_nats::Client>>,
    core: &CoreServices,
    services: &PlatformServices,
    limiters: &RateLimiters,
    bg_shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let secrets_manager = core.secrets_manager.clone();
    let registry = core.registry.clone();
    let auth_service = services.auth_service.clone();
    let api_key_service = services.api_key_service.clone();
    let oauth_service = services.oauth_service.clone();
    let webhook_router = services.webhook_router.clone();
    let module_execution_service = services.module_execution_service.clone();
    let worker_shared_key = services.worker_shared_key.clone();
    let auth_rate_limiter = services.auth_rate_limiter.clone();
    let api_limiter = limiters.api_limiter.clone();
    let webhook_limiter = limiters.webhook_limiter.clone();
    // ---------- Start background session cleanup task ----------
    // MCP-1043 (2026-05-15): the three auth-data DELETE sweeps below
    // (sessions / API keys / OAuth state tokens) now subscribe to
    // bg_shutdown_rx via tokio::select. Each issues
    // `DELETE FROM <credential_table>` statements; a mid-tick
    // SIGTERM abort can wedge the connection-pool entry on
    // Postgres-side until the server-side query timeout fires.
    // Same pattern as the canonical LLM-keys / bcrypt-cache /
    // stale_execution_cleanup (MCP-1042) sweeps.
    let cleanup_auth_service = auth_service.clone();
    let session_cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = session_cleanup_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match cleanup_auth_service.cleanup_expired_sessions().await {
                        Ok(count) => {
                            if count > 0 {
                                tracing::info!("Cleaned up {} expired sessions", count);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to cleanup expired sessions: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Session cleanup loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("Session cleanup task started (runs every 5 minutes)");

    // ---------- Start background API key cleanup task ----------
    let cleanup_api_key_service = api_key_service.clone();
    let api_key_cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = api_key_cleanup_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match cleanup_api_key_service.cleanup_expired_keys().await {
                        Ok(count) => {
                            if count > 0 {
                                tracing::info!("Deactivated {} expired API keys", count);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to cleanup expired API keys: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("API key cleanup loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("API key cleanup task started (runs every hour)");

    // ---------- Start background OAuth state token cleanup task ----------
    let cleanup_oauth_service = oauth_service.clone();
    let oauth_cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = oauth_cleanup_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match cleanup_oauth_service.cleanup_expired_state_tokens().await {
                        Ok(count) => {
                            if count > 0 {
                                tracing::info!("Cleaned up {} expired OAuth state tokens", count);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to cleanup expired OAuth state tokens: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("OAuth state token cleanup loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("OAuth state token cleanup task started (runs every hour)");

    // ---------- Start workflow execution cleanup task ----------
    let cleanup_pool = db_pool.clone();
    // MCP-622 (2026-05-12): use `talos_config::execution_retention_days()`
    // instead of a hardcoded `7`. Pre-fix the helper existed (defaulting
    // to 30) but had ZERO callers — operators who set
    // `EXECUTION_RETENTION_DAYS=90` thinking they were extending
    // retention had data silently deleted at 7 days. The
    // `execution_max_rows()` sibling helper also has no callers but is
    // not used by this task (separate ceiling concern). Cache the value
    // once at task start so a mid-process env mutation can't make the
    // window jitter unpredictably between iterations; operators
    // re-deploy to change retention.
    let retention_days = talos_config::execution_retention_days();
    // MCP-1044: subscribe to bg_shutdown_rx so SIGTERM exits the
    // retention-DELETE loop cleanly between top-level ticks. Inner
    // batched-DELETE chunks still run to natural completion within
    // one tick (5K-row chunks complete in seconds); the shutdown
    // select gates the OUTER 6-hour ticker only.
    let exec_retention_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = exec_retention_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Delete executions older than `retention_days` (skip queued executions).
                    // Batched in chunks of 5000 to avoid long-held row locks and
                    // WAL bloat on the first run (or after a long outage).
                    let mut total_deleted = 0u64;
                    loop {
                        match sqlx::query(
                            "DELETE FROM workflow_executions \
                             WHERE id IN ( \
                                 SELECT id FROM workflow_executions \
                                 WHERE started_at < NOW() - INTERVAL '1 day' * $1 \
                                   AND status != 'queued' \
                                 LIMIT 5000 \
                             )",
                        )
                        .bind(retention_days)
                        .execute(&cleanup_pool)
                        .await
                        {
                            Ok(result) => {
                                let batch = result.rows_affected();
                                total_deleted += batch;
                                if batch < 5000 {
                                    break; // last batch — done
                                }
                                // Yield between batches to avoid monopolising the pool.
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                            Err(e) => {
                                tracing::error!("Failed to cleanup old workflow executions: {}", e);
                                break;
                            }
                        }
                    }
                    if total_deleted > 0 {
                        tracing::info!(
                            "Cleaned up {} old workflow executions (older than {} days)",
                            total_deleted,
                            retention_days
                        );
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Workflow execution retention loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!(
        retention_days,
        "Workflow execution cleanup task started (runs every 6 hours, EXECUTION_RETENTION_DAYS)"
    );

    // ---------- Start execution archival task ----------
    // MCP-1044: subscribe to bg_shutdown_rx — this daily sweep issues
    // a transactional CTE that DELETEs from workflow_executions and
    // INSERTs into workflow_executions_archive in a single statement.
    // Mid-statement abort on SIGTERM would leave the transaction in
    // an uncommitted state (rolled back by Postgres) but the
    // connection-pool entry stuck until the server-side timeout. The
    // shutdown gate makes the exit point predictable.
    let archive_pool = db_pool.clone();
    let archive_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = archive_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400)); // daily
        loop {
            let tick_result = tokio::select! {
                _ = interval.tick() => Some(()),
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Execution archival loop received shutdown signal");
                        None
                    } else {
                        Some(())
                    }
                }
            };
            if tick_result.is_none() {
                break;
            }
            // Prefer DB setting over env var.
            // MCP-758 (2026-05-13): filter `db_days <= 0` so the DB-stored
            // override path matches the env-side hardening from MCP-643.
            // Pre-fix a `system_settings.value = 0` row took
            // db_days.unwrap_or(env_days) → 0, then bound 0 into
            // `make_interval(days => $1::int)` below — "completed_at < NOW() -
            // 0 days" matches every completed/failed/cancelled execution
            // ever, archiving the entire table at the next daily tick.
            // Negative DB values would have the same effect (Postgres
            // accepts negative make_interval; "older than -7 days" =
            // "older than now + 7 days" = also everything). Same =0
            // destructive class as MCP-703 (DB-stored fuel_budget) and
            // MCP-643 (env-side ARCHIVE_AFTER_DAYS). The DB row can be
            // written via admin SQL — there's no public API path that
            // sets it today, but defense-in-depth before a future admin
            // surface is cheap. Warn on the misconfiguration so an
            // operator who deliberately wrote 0/negative gets a clear
            // signal that the value was ignored.
            // MCP-961 sibling: saturating i64→i32 conversion. Sibling
            // of the advanced.rs fix — operator-supplied DB value
            // could exceed i32::MAX and silently wrap pre-fix.
            let db_days: Option<i32> = sqlx::query_scalar::<_, serde_json::Value>(
                "SELECT value FROM system_settings WHERE key = 'archive_after_days'",
            )
            .fetch_optional(&archive_pool)
            .await
            .unwrap_or(None)
            .and_then(|v| {
                v.as_i64()
                    .map(|n| i32::try_from(n).unwrap_or(i32::MAX))
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            });
            let env_days = talos_config::positive_env_or_default::<i32>("ARCHIVE_AFTER_DAYS", 30);
            let days = match db_days {
                Some(d) if d > 0 => d,
                Some(d) => {
                    tracing::warn!(
                        target: "talos_engine",
                        event_kind = "archive_after_days_nonpositive_substituted",
                        configured = d,
                        fallback = env_days,
                        "system_settings.archive_after_days = {} is non-positive — \
                         ignored to prevent archiving every completed execution; \
                         falling back to env-derived value",
                        d
                    );
                    env_days
                }
                None => env_days,
            };
            // Move old completed/failed/cancelled executions to archive
            let result = sqlx::query(
                "WITH archived AS (
                    DELETE FROM workflow_executions
                    WHERE status IN ('completed', 'failed', 'cancelled')
                    AND completed_at < NOW() - make_interval(days => $1::int)
                    AND is_pinned = false
                    RETURNING *
                )
                INSERT INTO workflow_executions_archive SELECT * FROM archived",
            )
            .bind(days)
            .execute(&archive_pool)
            .await;
            if let Ok(r) = result {
                if r.rows_affected() > 0 {
                    tracing::info!(count = r.rows_affected(), "Archived old executions");
                }
            }
        }
    });
    tracing::info!("Execution archival task started (runs daily, archives executions older than ARCHIVE_AFTER_DAYS env var, default 30)");

    // ---------- Start audit log cleanup task ----------
    // MCP-1045: subscribe to bg_shutdown_rx so SIGTERM exits the
    // hourly check loop cleanly. Audit log cleanup issues 3 DELETE
    // calls (auth + secret + webhook) once per day at 2 AM; outer
    // hourly ticker is what needs interruptibility.
    let cleanup_auth = auth_service.clone();
    let cleanup_secrets = secrets_manager.clone();
    let cleanup_webhooks = webhook_router.clone();
    let audit_cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = audit_cleanup_shutdown;
        // Run daily at 2 AM (check every hour, but only execute once per day)
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        let mut last_cleanup_day: Option<u32> = None;

        loop {
            let should_proceed = tokio::select! {
                _ = interval.tick() => true,
                _ = shutdown.changed() => !*shutdown.borrow(),
            };
            if !should_proceed {
                tracing::info!("Audit log cleanup loop received shutdown signal");
                break;
            }

            // Only run cleanup once per day at 2 AM
            use chrono::{Datelike, Timelike};
            let now = chrono::Utc::now();
            let current_day = now.ordinal(); // Day of year (1-indexed)
            let current_hour = now.hour();

            if current_hour == 2 && last_cleanup_day != Some(current_day) {
                // MCP-643: =0 would delete every audit log row (anything
                // older than 0 days = everything). Destructive class.
                let retention_days =
                    talos_config::positive_env_or_default::<i64>("AUDIT_LOG_RETENTION_DAYS", 90);

                tracing::info!(
                    "Starting audit log cleanup (retention: {} days)",
                    retention_days
                );

                // Clean up auth audit logs
                match cleanup_auth.cleanup_audit_logs(retention_days).await {
                    Ok(count) => {
                        if count > 0 {
                            tracing::info!("Cleaned up {} auth audit log entries", count);
                        }
                    }
                    Err(e) => tracing::error!("Failed to cleanup auth audit logs: {}", e),
                }

                // Clean up secret audit logs
                match cleanup_secrets.cleanup_audit_logs(retention_days).await {
                    Ok(count) => {
                        if count > 0 {
                            tracing::info!("Cleaned up {} secret audit log entries", count);
                        }
                    }
                    Err(e) => tracing::error!("Failed to cleanup secret audit logs: {}", e),
                }

                // Clean up webhook request logs
                match cleanup_webhooks.cleanup_request_logs(retention_days).await {
                    Ok(count) => {
                        if count > 0 {
                            tracing::info!("Cleaned up {} webhook request log entries", count);
                        }
                    }
                    Err(e) => tracing::error!("Failed to cleanup webhook request logs: {}", e),
                }

                // Clean up webhook dead-letter-queue rows. Dropped-request
                // payloads (DLP-redacted) accumulate forever without this
                // sweep — an unbounded storage-exhaustion vector under a
                // circuit-breaker / rate-limit flood against a known trigger.
                match cleanup_webhooks.cleanup_dlq(retention_days).await {
                    Ok(count) => {
                        if count > 0 {
                            tracing::info!("Cleaned up {} webhook DLQ entries", count);
                        }
                    }
                    Err(e) => tracing::error!("Failed to cleanup webhook DLQ: {}", e),
                }

                last_cleanup_day = Some(current_day);
                tracing::info!("Audit log cleanup completed");
            }
        }
    });
    tracing::info!("Audit log cleanup task started (runs daily at 2 AM)");

    // ---------- Expire timed-out workflow suspensions every 5 minutes ----------
    // MCP-1044: subscribe to bg_shutdown_rx — issues UPDATE
    // workflow_suspensions; mid-statement abort wedges the
    // connection pool until server-side timeout.
    let suspension_expiry_pool = db_pool.clone();
    let suspension_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = suspension_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match sqlx::query(
                        "UPDATE workflow_suspensions \
                         SET status = 'expired', resumed_by = 'timeout_expiry', resumed_at = now() \
                         WHERE status = 'waiting' AND timeout_at IS NOT NULL AND timeout_at < now()",
                    )
                    .execute(&suspension_expiry_pool)
                    .await
                    {
                        Ok(r) if r.rows_affected() > 0 => {
                            tracing::info!(
                                expired = r.rows_affected(),
                                "Expired timed-out workflow suspensions"
                            );
                        }
                        Err(e) => tracing::error!("Failed to expire workflow suspensions: {}", e),
                        _ => {}
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Suspension expiry loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("Suspension expiry task started (runs every 5 minutes)");

    // ---------- Start WASM module cache cleanup task ----------
    let cleanup_registry = registry.clone();
    tokio::spawn(async move {
        // Run every 6 hours
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(21600));

        loop {
            interval.tick().await;

            // MCP-643: =0 on any of these would purge the entire WASM
            // cache on the next sweep (retention=0 days, max=0 entries,
            // size cap=0 MB). Recoverable (re-pull from OCI) but
            // operationally costly. Substitute defaults + WARN.
            let retention_days =
                talos_config::positive_env_or_default::<i64>("WASM_CACHE_RETENTION_DAYS", 30);
            let max_modules =
                talos_config::positive_env_or_default::<i64>("WASM_CACHE_MAX_MODULES", 1000);
            let max_size_mb =
                talos_config::positive_env_or_default::<i64>("WASM_CACHE_MAX_SIZE_MB", 500);

            // Clean up old modules
            match cleanup_registry.cleanup_old_modules(retention_days).await {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!(
                            "Cleaned up {} old WASM modules (>{}d)",
                            count,
                            retention_days
                        );
                    }
                }
                Err(e) => tracing::error!("Failed to cleanup old WASM modules: {}", e),
            }

            // Enforce cache size limits
            match cleanup_registry
                .enforce_cache_limits(max_modules, max_size_mb)
                .await
            {
                Ok((modules_deleted, bytes_freed)) => {
                    if modules_deleted > 0 || bytes_freed > 0 {
                        tracing::info!(
                            "Evicted {} WASM modules (freed {} modules, {} MB)",
                            modules_deleted,
                            modules_deleted,
                            bytes_freed
                        );
                    }
                }
                Err(e) => tracing::error!("Failed to enforce WASM cache limits: {}", e),
            }

            // Log cache stats
            match cleanup_registry.get_cache_stats().await {
                Ok(stats) => {
                    tracing::debug!(
                        "WASM cache stats: {} modules, {:.2} MB, {} total uses",
                        stats.module_count,
                        stats.total_size_mb,
                        stats.total_usage_count
                    );
                }
                Err(e) => tracing::error!("Failed to get WASM cache stats: {}", e),
            }
        }
    });
    tracing::info!("WASM cache cleanup task started (runs every 6 hours)");

    // ---------- Start webhook rate-limiter + circuit-breaker cleanup task ----------
    // Prevents unbounded growth of in-memory token buckets and CB records as unique
    // webhook tokens and IPs accumulate over the process lifetime.
    let cleanup_webhook_rl = webhook_router.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Every 5 min
        loop {
            interval.tick().await;
            cleanup_webhook_rl.cleanup_rate_limiter();
            cleanup_webhook_rl.cleanup_circuit_breaker();
        }
    });
    tracing::info!(
        "Webhook rate-limiter + circuit-breaker cleanup task started (runs every 5 minutes)"
    );

    // ---------- Start IP rate-limiter cleanup task (MCP-694) ----------
    // The governor `RateLimiter<String, DashMapStateStore<String>>` for
    // `api_limiter` and `webhook_limiter` retains one DashMap entry per
    // distinct source IP forever. Under sustained traffic from many
    // distinct IPs (botnet sweeps, public internet exposure) the maps
    // grow without bound — at ~150 bytes per entry, 1M unique IPs
    // ≈ 150 MB per limiter. `retain_recent()` drops keys whose buckets
    // are indistinguishable from a "fresh" state (idle long enough that
    // they hit no rate-limit cost on next encounter); `shrink_to_fit()`
    // reclaims the DashMap capacity. Both are governor-provided
    // (governor 0.6.3 src/state/keyed.rs:180,191).
    //
    // Same 5-min cadence as the webhook cleanup above so operators see
    // one consistent rate-limiter-hygiene heartbeat in logs.
    let cleanup_api_limiter = api_limiter.clone();
    let cleanup_webhook_ip_limiter = webhook_limiter.clone();
    // MCP-718 (2026-05-13): add the `DistributedRateLimiter`'s in-memory
    // fallback to the same sweep. Under FailOpen Redis outages the
    // fallback accumulates one DashMap entry per distinct auth-attempt
    // identifier; entries SURVIVE Redis recovery (governor's keyed
    // state store has no auto-eviction). Wiring through the new
    // `cleanup_fallback()` helper keeps the contract identical to the
    // raw-limiter sweep above without leaking the inner `IpRateLimiter`
    // out of `DistributedRateLimiter`.
    let cleanup_auth_limiter = auth_rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        // First tick fires immediately — burn it so a fresh boot doesn't
        // do an empty-map walk before any request has been admitted.
        interval.tick().await;
        loop {
            interval.tick().await;
            let api_before = cleanup_api_limiter.len();
            cleanup_api_limiter.retain_recent();
            cleanup_api_limiter.shrink_to_fit();
            let api_after = cleanup_api_limiter.len();

            let wh_before = cleanup_webhook_ip_limiter.len();
            cleanup_webhook_ip_limiter.retain_recent();
            cleanup_webhook_ip_limiter.shrink_to_fit();
            let wh_after = cleanup_webhook_ip_limiter.len();

            let auth_before = cleanup_auth_limiter.fallback_len();
            cleanup_auth_limiter.cleanup_fallback();
            let auth_after = cleanup_auth_limiter.fallback_len();

            if api_before > api_after || wh_before > wh_after || auth_before > auth_after {
                tracing::info!(
                    target: "talos_rate_limit",
                    event_kind = "ip_rate_limiter_sweep",
                    api_before, api_after,
                    webhook_before = wh_before,
                    webhook_after = wh_after,
                    auth_fallback_before = auth_before,
                    auth_fallback_after = auth_after,
                    "IP rate-limiter cleanup: dropped idle buckets"
                );
            }
        }
    });
    tracing::info!(
        "IP rate-limiter cleanup task started (runs every 5 minutes, retain_recent + shrink_to_fit; covers api + webhook + auth-fallback)"
    );

    // ---------- Start stuck execution cleanup task ----------
    // Transitions orphaned `pending`/`running` executions to `timeout` when a
    // worker crashes without reporting a result.
    //
    // MCP-1044: subscribe to bg_shutdown_rx — issues
    // UPDATE workflow_executions; mid-statement abort wedges the
    // connection pool. Same MCP-1042/1043 discipline.
    let cleanup_exec_service = module_execution_service.clone();
    let stuck_cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = stuck_cleanup_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // MCP-643: =0 would mark every running execution as stuck
                    // immediately (anything older than 0 mins = everything),
                    // including healthy in-progress jobs.
                    let max_age_mins =
                        talos_config::positive_env_or_default::<i64>("STUCK_EXECUTION_TIMEOUT_MINS", 30);
                    match cleanup_exec_service
                        .cleanup_stuck_executions(max_age_mins)
                        .await
                    {
                        Ok(count) if count > 0 => tracing::warn!(
                            "Cleaned up {} stuck executions (idle > {} min)",
                            count,
                            max_age_mins
                        ),
                        Ok(_) => {}
                        Err(e) => tracing::error!("Failed to cleanup stuck executions: {}", e),
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Stuck execution cleanup loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("Stuck execution cleanup task started (runs every 5 minutes, timeout after 30 min by default)");

    // ---------- Crash recovery: resume checkpointed executions ----------
    // RFC 0003 (durable execution). On a controller restart, executions that
    // were mid-flight are wedged in `running` — their in-process engine task
    // died with the process. When EXECUTION_CHECKPOINTING_ENABLED is on, the
    // engine persisted node-result checkpoints; this one-shot startup sweep
    // claims those orphans (`running -> resuming`, FOR UPDATE SKIP LOCKED so
    // it's exactly-once across replicas) and resumes each from its last
    // checkpoint via the NATS seed path.
    //
    // ONE-SHOT at startup (not periodic) on purpose: at startup there are no
    // live in-process engine tasks from THIS process, so any orphaned
    // `running` row is genuinely dead. A periodic sweep in a single-replica
    // deployment could claim a long-running-but-alive execution (one whose
    // current node runs longer than the stale window without a checkpoint
    // heartbeat) and double-dispatch it.
    //
    // Requires NATS (the resume dispatch goes over signed NATS-RPC) and the
    // checkpointing flag — without checkpoints there is nothing to resume.
    if talos_config::bool_env_or_default("EXECUTION_CHECKPOINTING_ENABLED", false) {
        if let Some(nats_for_recovery) = nats_client.clone() {
            // Resume orphans idle beyond this window. MUST be smaller than
            // STUCK_EXECUTION_TIMEOUT_MINS (default 30) so a recoverable
            // execution is resumed before any cleanup path could fail it.
            let resume_stale_mins =
                talos_config::positive_env_or_default::<i64>("EXECUTION_RESUME_STALE_MINS", 5);
            let stuck_timeout_mins =
                talos_config::positive_env_or_default::<i64>("STUCK_EXECUTION_TIMEOUT_MINS", 30);
            if resume_stale_mins >= stuck_timeout_mins {
                tracing::warn!(
                    resume_stale_mins,
                    stuck_timeout_mins,
                    "EXECUTION_RESUME_STALE_MINS >= STUCK_EXECUTION_TIMEOUT_MINS — orphaned \
                     executions may be failed by stuck-cleanup before crash recovery can claim them"
                );
            }
            let recovery_deps = talos_execution_orchestration::RecoveryDeps {
                db_pool: db_pool.clone(),
                registry: registry.clone(),
                secrets_manager: secrets_manager.clone(),
                actor_repo: std::sync::Arc::new(actor_repository::ActorRepository::new(
                    db_pool.clone(),
                )),
                execution_repo: std::sync::Arc::new(
                    crate::execution_repository::ExecutionRepository::new(db_pool.clone()),
                ),
                worker_shared_key: worker_shared_key.clone(),
                nats_client: nats_for_recovery,
            };
            tokio::spawn(async move {
                talos_execution_orchestration::recover_stuck_executions(
                    recovery_deps,
                    resume_stale_mins,
                )
                .await;
            });
            tracing::info!(
                "Crash-recovery startup sweep spawned (EXECUTION_CHECKPOINTING_ENABLED on); \
                 resuming executions idle > {} min from their last checkpoint",
                resume_stale_mins
            );
        } else {
            tracing::warn!(
                "EXECUTION_CHECKPOINTING_ENABLED is on but NATS is unavailable — \
                 crash-recovery sweep skipped (resume dispatch needs NATS)"
            );
        }
    }

    // ---------- Start DEK cache cleanup task ----------
    // Evicts expired DEK entries from the in-memory HashMap to prevent unbounded
    // growth in long-lived processes.  DEK rotation is rare, so the cache stays
    // small in practice, but the cleanup ensures stale entries are released.
    let cleanup_secrets_dek = secrets_manager.clone();
    tokio::spawn(async move {
        // Run every 10 minutes — DEK TTL is 5 min by default, so this evicts
        // entries within one extra TTL period of expiry.
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
        loop {
            interval.tick().await;
            cleanup_secrets_dek.cleanup_expired_cache_entries().await;
        }
    });
    tracing::info!("DEK cache cleanup task started (runs every 10 minutes)");

    // ---------- Start actor memory TTL cleanup task ----------
    // Deletes expired actor_memory rows (working=1h, episodic=7d,
    // scratchpad=24h TTLs stored in expires_at; semantic rows never
    // expire). Goes through `talos_memory::sweep_expired` so the
    // single canonical service owns every direct write to the
    // table — no inline DELETE queries elsewhere in the codebase.
    let agent_memory_pool = db_pool.clone();
    let actor_memory_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = actor_memory_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(900)); // Every 15 min
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Grace = 0: expired rows are deleted immediately on each
                    // tick. Override here if we ever want to retain
                    // tombstones longer than their TTL for forensics.
                    match talos_memory::sweep_expired(&agent_memory_pool, 0).await {
                        Ok(0) => {}
                        Ok(n) => tracing::debug!(count = n, "Cleaned up expired actor_memory entries"),
                        Err(e) => tracing::error!("Failed to cleanup actor_memory TTL: {}", e),
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Actor-memory TTL sweep loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("Actor memory TTL cleanup task started (runs every 15 minutes)");
}

/// Graph RAG service (Neo4j) init — TLS prod gate, vault-first key
/// resolution, and the tier-1 data-egress gate. Extracted verbatim from
/// `main()`.
async fn init_graph_rag(
    secrets_manager: std::sync::Arc<SecretsManager>,
    actor_repo: std::sync::Arc<actor_repository::ActorRepository>,
) -> anyhow::Result<()> {
    // ---------- Initialize Graph RAG service (Neo4j) ----------
    {
        // SECURITY: In production, REFUSE to start on a plaintext Neo4j URI.
        // Graph-RAG traffic can carry actor data; only the TLS schemes encrypt
        // it on the wire (HIPAA §164.312(e) / SOC2 CC6.7). This gate lives here
        // (not inside GraphRagService::new) because the call site below treats
        // an init Err as "continue without graph" — a misconfigured plaintext
        // URI must hard-fail the boot, not silently disable graph-RAG.
        // tls-prod-gate-neo4j
        if let Ok(neo4j_uri) = std::env::var("NEO4J_URI") {
            if !neo4j_uri.is_empty()
                && crate::config::is_production()
                && !neo4j_uri.starts_with("neo4j+s://")
                && !neo4j_uri.starts_with("neo4j+ssc://")
                && !neo4j_uri.starts_with("bolt+s://")
                && !neo4j_uri.starts_with("bolt+ssc://")
            {
                return Err(anyhow::anyhow!(
                    "NEO4J_URI must use a TLS scheme (neo4j+s://, neo4j+ssc://, bolt+s://, or \
                     bolt+ssc://) in production — refusing to start. Got scheme: '{}'.",
                    neo4j_uri.split("://").next().unwrap_or("<unknown>")
                ));
            }
        }
        match graph_rag::GraphRagService::new().await {
            Ok(Some(service)) => {
                // Vault-first Anthropic key resolution AND tier-1
                // data-egress gate. Without `with_actor_repo`, the
                // LLM-fallback extraction path would send memory
                // contents to Anthropic regardless of the actor's
                // `max_llm_tier` ceiling — a policy bypass for
                // tier1 (local-only) actors. The fail-closed tier
                // check inside the service blocks the call when
                // the lookup errors or the actor row is missing.
                let mut service = service
                    .with_secrets(secrets_manager.clone())
                    .with_actor_repo(actor_repo.clone());

                // Local-Ollama fallback for provider-agnostic triple
                // extraction: on Ollama-only / self-hosted deployments
                // (no anthropic/api_key), this is what populates the
                // knowledge graph — extraction routes to the local
                // model instead of no-op'ing. Anthropic stays preferred
                // when a key resolves; the tier1 data-egress gate still
                // applies to BOTH backends. Same `OLLAMA_URL` default
                // the MCP Ollama handlers use; `TALOS_GRAPH_RAG_MODEL`
                // picks the extraction model (any instruct model present
                // in the deployment's Ollama).
                let ollama_url = talos_config::get_env("OLLAMA_URL", "http://ollama:11434");
                let graph_rag_model = talos_config::get_env("TALOS_GRAPH_RAG_MODEL", "qwen2.5:7b");
                let ollama_wired = !ollama_url.is_empty() && !graph_rag_model.is_empty();
                if ollama_wired {
                    let ollama_client =
                        std::sync::Arc::new(talos_llm::OllamaClient::new(ollama_url.clone()));
                    service = service.with_ollama(ollama_client, graph_rag_model.clone());
                    tracing::info!(
                        ollama_url = %ollama_url,
                        model = %graph_rag_model,
                        "Graph RAG local-Ollama extraction backend wired (fallback when no anthropic/api_key)"
                    );
                }

                // TALOS_GRAPH_RAG_TIER1_LOCAL_OK — operator attestation
                // that the Ollama endpoint above runs ON-HOST, unlocking
                // graph extraction for tier1 (local-only) actors via the
                // LOCAL backend only (never Anthropic; see
                // `with_tier1_local_extraction` for the full security
                // semantics). Empty-env hardening: unset/"" → off;
                // explicit truthy ("1"/"true"/"yes") → on; anything else
                // → off with a WARN (a typo like "on" must not silently
                // disable a knob the operator believes is enabled —
                // sibling of the MCP-590 empty-env class).
                let tier1_local_raw = std::env::var("TALOS_GRAPH_RAG_TIER1_LOCAL_OK")
                    .ok()
                    .filter(|v| !v.is_empty());
                let tier1_local_ok = match tier1_local_raw.as_deref() {
                    Some(v) if matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes") => {
                        true
                    }
                    Some(v) if matches!(v.to_ascii_lowercase().as_str(), "0" | "false" | "no") => {
                        false
                    }
                    Some(v) => {
                        tracing::warn!(
                            value = %v,
                            "TALOS_GRAPH_RAG_TIER1_LOCAL_OK set to an unrecognized value — \
                             treating as OFF. Use 1/true/yes to enable."
                        );
                        false
                    }
                    None => false,
                };
                if tier1_local_ok {
                    if ollama_wired {
                        service = service.with_tier1_local_extraction(true);
                        tracing::info!(
                            ollama_url = %ollama_url,
                            "Graph RAG tier1 local extraction ENABLED — operator attests the \
                             Ollama endpoint is on-host; tier1 actors' memories will be sent \
                             to the LOCAL model (never an external provider) for graph \
                             extraction"
                        );
                    } else {
                        tracing::warn!(
                            "TALOS_GRAPH_RAG_TIER1_LOCAL_OK is set but no Ollama extraction \
                             backend is wired (OLLAMA_URL / TALOS_GRAPH_RAG_MODEL empty) — \
                             tier1 actors still skip graph extraction"
                        );
                    }
                }

                let _ = actor_memory_service::GRAPH_SERVICE.set(service);
                actor_memory_service::install_graph_hook();
                tracing::info!("Graph RAG service initialized and registered with talos-memory");
            }
            Ok(None) => {
                tracing::info!("Graph RAG service disabled (NEO4J_URI not set)");
            }
            Err(e) => {
                tracing::warn!(
                    "Graph RAG service failed to initialize: {} — continuing without graph",
                    e
                );
            }
        }
    }

    Ok(())
}

/// Opt-in registration of the Redis-backed distributed replay guard
/// (codebase-review finding #2). No-op unless `TALOS_DISTRIBUTED_REPLAY` is
/// truthy; logs loudly (but does not fail boot) if enabled without a reachable
/// Redis, since HMAC + freshness + the per-replica nonce cache still protect
/// against forgery and within-replica replay — the shared guard only adds
/// cross-replica single-use.
async fn register_distributed_replay_guard(redis_client: Option<&std::sync::Arc<redis::Client>>) {
    let enabled = matches!(
        std::env::var("TALOS_DISTRIBUTED_REPLAY").ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    );
    if !enabled {
        return;
    }
    let Some(client) = redis_client else {
        tracing::warn!(
            target: "talos_security",
            "TALOS_DISTRIBUTED_REPLAY is on but REDIS_URL is unset — cross-replica replay \
             protection NOT active (per-replica nonce cache only)"
        );
        return;
    };
    match talos_replay_guard::RedisReplayGuard::connect(client).await {
        Ok(guard) => {
            match talos_replay_guard::register_shared_replay_guard(std::sync::Arc::new(guard)) {
                Ok(()) => tracing::info!(
                    target: "talos_security",
                    fail_closed = talos_replay_guard::fail_closed_from_env(),
                    "distributed replay guard registered (Redis) — cross-replica RPC replay \
                     protection active"
                ),
                Err(e) => tracing::error!(
                    target: "talos_security",
                    error = %e,
                    "failed to register distributed replay guard"
                ),
            }
        }
        Err(e) => tracing::error!(
            target: "talos_security",
            error = %e,
            "TALOS_DISTRIBUTED_REPLAY is on but connecting the Redis replay guard failed — \
             cross-replica protection NOT active"
        ),
    }
}

/// Register the HMAC verify-ring for the talos-memory RPC subscribers and
/// compute whether the subscribers may start. MUST run before
/// `wire_rpc_subscribers` — registration-before-subscribe is the invariant
/// (verify() fails closed otherwise). Extracted verbatim from `main()`.
fn register_rpc_hmac_ring() -> anyhow::Result<bool> {
    // ---------- Register HMAC key for talos-memory RPC subscribers ----------
    // Both the graph-search and memory-op RPCs require an HMAC-signed
    // request. Workers sign with WORKER_SHARED_KEY; we register the
    // same secret here so the subscribers can verify. Registration
    // must happen before any subscriber starts accepting messages,
    // otherwise verify() fails closed and every request returns
    // Unauthorized.
    // Load the full verify-ring (current + WORKER_SHARED_KEY_PREVIOUS) so the
    // RPC subscribers accept signatures made under a staged previous key during
    // a rolling WORKER_SHARED_KEY rotation. Workers SIGN their RPC requests with
    // the current key only; the controller VERIFIES, so the ring lives here.
    match talos_workflow_job_protocol::load_worker_key_ring() {
        Ok(ring) => {
            // M-3: log the same fingerprint format the worker emits at startup
            // so operators can grep both process logs for `worker_shared_key_fp=`
            // and confirm they agree. A signing-key mismatch means controller
            // and worker were configured with different env values — every
            // signed RPC fails verification, opaquely, until this line reveals
            // the drift. During rotation we also log each accepted previous-key
            // fingerprint so the staged ring is auditable across the fleet.
            tracing::info!(
                worker_shared_key_fp =
                    %talos_workflow_job_protocol::worker_key_fingerprint(ring.signing_key().as_bytes()),
                verify_key_count = ring.verify_keys().len(),
                "WORKER_SHARED_KEY loaded; compare this fingerprint against the worker's log line for drift detection"
            );
            for prev in ring.verify_keys().iter().skip(1) {
                tracing::info!(
                    previous_worker_shared_key_fp =
                        %talos_workflow_job_protocol::worker_key_fingerprint(prev.as_bytes()),
                    "WORKER_SHARED_KEY_PREVIOUS accepted for RPC verification (rotation in progress)"
                );
            }
            let signing = std::sync::Arc::new(ring.signing_key().as_bytes().to_vec());
            let previous: Vec<std::sync::Arc<Vec<u8>>> = ring
                .verify_keys()
                .iter()
                .skip(1)
                .map(|k| std::sync::Arc::new(k.as_bytes().to_vec()))
                .collect();
            talos_memory::rpc_auth::register_hmac_key_ring(signing, previous);
            tracing::info!("talos-memory RPC HMAC verify-ring registered");
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "WORKER_SHARED_KEY unavailable — talos-memory RPC subscribers will reject all requests"
            );
        }
    }

    // MCP-911 (2026-05-14): fail-fast on missing HMAC key in production.
    // Pre-fix the controller continued past the error log above and
    // spawned 5 RPC subscribers (graph/memory/database/state/integration)
    // that ALL rejected every incoming message as Unauthorized. Workers
    // saw `verify_no_replay` failures with no signal back to the
    // controller side that the key wasn't registered. `rpc_auth::is_ready()`
    // was built precisely for this gate (per its doc comment: "Exposed
    // so subscribers can refuse to start if auth is not configured")
    // but had been dead.
    //
    // In production: return Err to refuse boot.
    // In dev: WARN and skip spawning the RPC subscribers entirely
    //   (cleaner than spawning subscribers that always reject —
    //   worker dispatch will fail with "no responders" rather than
    //   "Unauthorized", which is a clearer operator signal).
    let rpc_subscribers_enabled = talos_memory::rpc_auth::is_ready();
    if !rpc_subscribers_enabled {
        if talos_config::is_production() {
            return Err(anyhow::anyhow!(
                "talos-memory RPC HMAC key not registered — WORKER_SHARED_KEY \
                 (or WORKER_SHARED_KEY_FILE) must be set in production. \
                 Subscribers would reject all messages as Unauthorized."
            ));
        } else {
            tracing::warn!(
                "talos-memory RPC HMAC key not registered — skipping RPC \
                 subscriber spawn. Set WORKER_SHARED_KEY to enable \
                 worker→controller dispatch."
            );
        }
    }

    Ok(rpc_subscribers_enabled)
}

/// Spawn the five signed NATS-RPC subscribers (graph / memory / database /
/// state / integration_state) plus the integration_state sweeper, and return
/// the shutdown handle the graceful-shutdown hook flips. Extracted verbatim
/// from `main()`; spawn order preserved.
fn wire_rpc_subscribers(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    nats_client: Option<std::sync::Arc<async_nats::Client>>,
    rpc_subscribers_enabled: bool,
    secrets_manager: std::sync::Arc<SecretsManager>,
) -> std::sync::Arc<tokio::sync::watch::Sender<bool>> {
    // ---------- Graph-search NATS-RPC subscriber (Phase 3) ----------
    // Workers can't reach the Neo4j driver directly (it's a
    // controller-side dependency), so the WIT `graph-memory::graph-search`
    // host function dispatches over NATS. This subscriber answers those
    // requests, scoping results to the requesting actor's subgraph and
    // clamping depth/limit to the protocol caps.
    // One shutdown watch channel drives graceful termination of all
    // four RPC subscribers. The axum ctrl_c hook (installed at the
    // end of main) flips the flag, each subscriber observes the
    // change via `shutdown_rx.changed()`, breaks its loop, and stops
    // accepting new work. In-flight requests continue to completion
    // because each request runs in its own tokio::spawn; we only
    // stop the subscribe-dispatch loop.
    let (rpc_shutdown_tx, rpc_shutdown_rx) = tokio::sync::watch::channel::<bool>(false);
    let rpc_shutdown_tx = std::sync::Arc::new(rpc_shutdown_tx);

    // MCP-911: each of these subscribers verifies HMAC on every
    // incoming message; spawning them when the key isn't registered
    // turns every RPC into an Unauthorized rejection storm. Gate on
    // `rpc_subscribers_enabled` (computed above) so dev clusters
    // without WORKER_SHARED_KEY come up cleanly with these endpoints
    // simply absent — production already aborted earlier in main.
    if rpc_subscribers_enabled {
        if let Some(nats) = nats_client.clone() {
            spawn_graph_rpc_subscriber(nats, rpc_shutdown_rx.clone());
        }
        if let Some(nats) = nats_client.clone() {
            spawn_memory_rpc_subscriber(nats, db_pool.clone(), rpc_shutdown_rx.clone());
        }
        if let Some(nats) = nats_client.clone() {
            spawn_database_rpc_subscriber(nats, db_pool.clone(), rpc_shutdown_rx.clone());
        }
        if let Some(nats) = nats_client.clone() {
            spawn_state_write_subscriber(nats, db_pool.clone(), rpc_shutdown_rx.clone());
        }
        if let Some(nats) = nats_client.clone() {
            spawn_integration_state_subscriber(nats, db_pool.clone(), rpc_shutdown_rx.clone());
        }
        if let Some(nats) = nats_client.clone() {
            // RFC 0011 P2c: `talos.ml.predict`. Context install before
            // spawn so no request races an unset OnceLock (an unset
            // context answers NotAvailable, never panics).
            let _ = rpc_subscribers::ML_PREDICT_CONTEXT.set(rpc_subscribers::MlPredictContext {
                db_pool: db_pool.clone(),
                dataset_service: talos_ml::DatasetService::new(secrets_manager),
            });
            spawn_ml_rpc_subscriber(nats.clone(), rpc_shutdown_rx.clone());
            // Few-shot corrections op shares the predict context.
            rpc_subscribers::spawn_ml_fewshot_subscriber(nats, rpc_shutdown_rx.clone());
        }
    }
    // Background sweep for expired integration_state rows. Runs
    // independent of NATS — always start since sweeping happens whether
    // or not the RPC subscriber is live.
    spawn_integration_state_sweeper(db_pool.clone(), rpc_shutdown_rx.clone());

    rpc_shutdown_tx
}

/// Actor-memory embedding backfill (one-shot), readiness-score
/// recomputation, and SLA degradation alerting. Extracted verbatim from
/// `main()`; spawn order preserved.
fn spawn_analytics_tasks(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    bg_shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    // ---------- Start actor memory embedding backfill (one-shot on startup) ----------
    {
        let backfill_pool = db_pool.clone();
        tokio::spawn(async move {
            // Small delay to let Ollama warm up after restart.
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            match actor_memory_service::backfill_embeddings(&backfill_pool, 100).await {
                Ok(n) => {
                    if n > 0 {
                        tracing::info!(embedded = n, "Actor memory embedding backfill completed");
                    }
                }
                Err(e) => tracing::warn!("Actor memory embedding backfill failed: {}", e),
            }
        });
    }

    // ---------- Start readiness score background recomputation task ----------
    // MCP-1045: subscribe to bg_shutdown_rx — issues per-workflow
    // UPDATE actor_readiness statements; mid-batch SIGTERM aborts
    // can leave readiness rows partially updated and wedge the
    // connection-pool entry on the in-flight UPDATE.
    let readiness_pool = db_pool.clone();
    let readiness_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = readiness_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Every hour
        loop {
            let should_proceed = tokio::select! {
                _ = interval.tick() => true,
                _ = shutdown.changed() => !*shutdown.borrow(),
            };
            if !should_proceed {
                tracing::info!("Readiness recomputation loop received shutdown signal");
                break;
            }

            // Fetch all workflows with stale or missing readiness scores
            let workflows: Vec<(
                uuid::Uuid,
                uuid::Uuid,
                Option<String>,
                Vec<String>,
                Option<String>,
            )> = match sqlx::query_as(
                "SELECT id, user_id, description, capabilities, graph_json \
                 FROM workflows \
                 WHERE readiness_computed_at IS NULL \
                    OR readiness_computed_at < NOW() - INTERVAL '1 hour' \
                 LIMIT 500",
            )
            .fetch_all(&readiness_pool)
            .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::error!("Readiness score batch query failed: {}", e);
                    continue;
                }
            };

            if workflows.is_empty() {
                continue;
            }

            let mut updated = 0u64;
            // MCP-778 (2026-05-13): track UPDATE failures alongside successes
            // so the operator-facing summary surfaces partial-batch DB issues.
            // See the `if updated > 0` log at the loop tail.
            let mut update_failed = 0u64;
            for (wf_id, wf_user_id, wf_desc, wf_caps, graph_json_str) in &workflows {
                let graph: serde_json::Value = graph_json_str
                    .as_deref()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or_else(|| serde_json::json!({"nodes":[],"edges":[]}));

                // Reliability (50%): success_rate * min(exec_count/10, 1.0)
                // Saturates at 10 runs — consistent with get_readiness_breakdown handler.
                // 5 perfect runs → 50% reliability credit (not alarming on operator dashboards).
                //
                // MCP-503: pair every `.unwrap_or` zero-fallback in this
                // background task with a `tracing::warn!`. Pre-fix the
                // inner queries silently swallowed DB errors, so a
                // column rename / FK violation / schema drift would
                // quietly downgrade every workflow's readiness score
                // with no operator-visible signal. Same lint-check-8
                // pattern fixed in MCP-488 (cost-attribution) and
                // MCP-489 (retry-intelligence). The outer batch query
                // at line ~1691 ALREADY logs-and-continues; this fix
                // brings the inner queries to parity.
                let perf_row: Option<(Option<f64>, i64)> = sqlx::query_as(
                    "SELECT \
                        (COUNT(*) FILTER (WHERE status = 'completed'))::float / NULLIF(COUNT(*), 0), \
                        COUNT(*) \
                     FROM workflow_executions \
                     WHERE workflow_id = $1 AND started_at > NOW() - interval '30 days'"
                ).bind(wf_id).fetch_optional(&readiness_pool).await.unwrap_or_else(|e| {
                    tracing::warn!(
                        %wf_id,
                        error = %e,
                        "readiness: workflow_executions perf query failed — using neutral reliability"
                    );
                    None
                });

                let (success_rate, exec_count) = perf_row.unwrap_or((None, 0));
                let reliability =
                    success_rate.unwrap_or(0.0) * (exec_count as f64 / 10.0).min(1.0) * 50.0;

                // Documentation (20%): has_desc=10, has_node_desc=5, has_caps=5
                // Consistent with get_readiness_breakdown handler.
                let has_desc = if wf_desc.as_ref().map(|d| !d.is_empty()).unwrap_or(false) {
                    10.0
                } else {
                    0.0
                };
                let has_node_desc = if graph
                    .get("nodes")
                    .and_then(|n| n.as_array())
                    .map(|nodes| {
                        nodes.iter().any(|n| {
                            n.get("description")
                                .and_then(|d| d.as_str())
                                .map(|s| !s.is_empty())
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false)
                {
                    5.0
                } else {
                    0.0
                };
                let has_caps = if !wf_caps.is_empty() { 5.0 } else { 0.0 };
                let documentation = has_desc + has_node_desc + has_caps;

                // Freshness (20%)
                let last_exec: Option<(Option<chrono::DateTime<chrono::Utc>>,)> = sqlx::query_as(
                    "SELECT MAX(started_at) FROM workflow_executions WHERE workflow_id = $1",
                )
                .bind(wf_id)
                .fetch_optional(&readiness_pool)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(
                        %wf_id,
                        error = %e,
                        "readiness: workflow_executions last-exec query failed — freshness scored 0"
                    );
                    None
                });

                let freshness = match last_exec.and_then(|r| r.0) {
                    Some(last) => {
                        let days_ago = chrono::Utc::now().signed_duration_since(last).num_days();
                        if days_ago <= 7 {
                            20.0
                        } else if days_ago <= 30 {
                            10.0
                        } else {
                            0.0
                        }
                    }
                    None => 0.0,
                };

                // Risk (10%)
                let has_timeout = graph.get("execution_timeout_secs").is_some();
                let has_error_edges = graph
                    .get("edges")
                    .and_then(|e| e.as_array())
                    .map(|edges| {
                        edges
                            .iter()
                            .any(|e| e.get("edge_type").and_then(|t| t.as_str()) == Some("error"))
                    })
                    .unwrap_or(false);
                let expiring_secrets: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM secrets WHERE created_by = $1 AND expires_at IS NOT NULL AND expires_at < NOW() + interval '7 days'"
                ).bind(wf_user_id).fetch_one(&readiness_pool).await.unwrap_or_else(|e| {
                    tracing::warn!(
                        %wf_user_id,
                        error = %e,
                        "readiness: expiring-secrets query failed — risk score will not reflect expiry"
                    );
                    0
                });

                let mut risk = 10.0_f64;
                if !has_timeout {
                    risk -= 3.0;
                }
                if !has_error_edges {
                    risk -= 3.0;
                }
                if expiring_secrets > 0 {
                    risk -= 4.0;
                }
                let risk = risk.max(0.0);

                let total = (reliability + documentation + freshness + risk).round() as i32;

                // MCP-778 (2026-05-13): replace `.is_ok()` swallow with a
                // success/failure split. Pre-fix the UPDATE error was
                // discarded — under sustained DB pressure (long-running
                // statement timeout, FK churn, partition lock), the
                // background recomputation showed "Recomputed readiness
                // scores for 0 workflows" even though hundreds of UPDATEs
                // were attempted-and-failed. Operators saw stale dashboard
                // readiness scores with NO log signal correlating the
                // staleness to DB health. Same MCP-503 observability rule
                // applied to the read-side queries in this same task
                // (line ~1911); this brings the write-side to parity.
                // High-volume loop → log a SUMMARY at end (not per-row)
                // to avoid spamming.
                match sqlx::query(
                    "UPDATE workflows SET readiness_score = $1, readiness_computed_at = NOW() WHERE id = $2"
                )
                .bind(total)
                .bind(wf_id)
                .execute(&readiness_pool)
                .await
                {
                    Ok(_) => updated += 1,
                    Err(_) => update_failed += 1,
                }
            }

            if updated > 0 || update_failed > 0 {
                if update_failed == 0 {
                    tracing::info!(
                        target: "talos_audit",
                        updated,
                        "Recomputed readiness scores for {} workflows", updated
                    );
                } else {
                    tracing::warn!(
                        target: "talos_audit",
                        updated,
                        update_failed,
                        total_processed = updated + update_failed,
                        "Recomputed readiness scores: {} succeeded, {} UPDATE failures — DB may be under pressure; readiness dashboard will show stale scores for the failed rows until next hourly tick",
                        updated,
                        update_failed
                    );
                }
            }
        }
    });
    tracing::info!("Readiness score recomputation task started (runs every hour)");

    // ---------- Start SLA degradation alerting task ----------
    // MCP-1045: subscribe to bg_shutdown_rx — issues INSERTs into
    // workflow_sla_alerts on threshold breach. Outer 15-min ticker
    // gated; inner per-workflow alert-emit loop runs to natural
    // completion within one tick.
    let sla_pool = db_pool.clone();
    let sla_degradation_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = sla_degradation_shutdown;
        // Wait 2 minutes after startup before first check to let executions settle
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(900)); // 15 min
                                                                                       // MCP-469: disable redirect following for SLA notification
                                                                                       // webhooks. The SSRF check at fire time validates the literal
                                                                                       // URL, but reqwest's default `Policy::limited(10)` would follow
                                                                                       // a 302/303 to an internal host beneath the SSRF gate. Matches
                                                                                       // the canonical pattern in approval_gate / failure_webhook.
                                                                                       //
                                                                                       // Fallback to `Client::new()` removed: that path re-enabled the
                                                                                       // default redirect policy and would silently reopen the SSRF
                                                                                       // gap. `.build()` rarely fails (TLS init issues only), and
                                                                                       // `Client::new()` would also panic on the same failure mode —
                                                                                       // so a loud `.expect()` is functionally equivalent and removes
                                                                                       // the false sense of recovery.
                                                                                       // MCP-1034: explicit connect_timeout (2s on 5s budget) so a
                                                                                       // black-holed SLA-webhook endpoint fails on connect rather than
                                                                                       // burning the whole loop tick.
                                                                                       // Built via the shared SSRF-safe builder: redirect(none) + the
                                                                                       // connect-time ControllerSsrfResolver. The SLA-alert webhook URL is
                                                                                       // user/workflow-supplied (SLA threshold config) and SSRF-checked at fire
                                                                                       // time, but that call-time check can't stop DNS rebinding — the same gap
                                                                                       // PR #162 closed for the sibling fire sites.
        let http_client = talos_http_utils::outbound::build_outbound_webhook_client_with_timeout(
            "talos-sla-webhook/1.0",
            std::time::Duration::from_secs(5),
        )
        .expect("SLA monitor: failed to build HTTP client with no-redirect policy");
        let analytics_repo = analytics_repository::AnalyticsRepository::new(sla_pool.clone());

        loop {
            let should_proceed = tokio::select! {
                _ = interval.tick() => true,
                _ = shutdown.changed() => !*shutdown.borrow(),
            };
            if !should_proceed {
                tracing::info!("SLA degradation alerting loop received shutdown signal");
                break;
            }

            // 1. Check workflows with explicit SLA thresholds
            let sla_rows: Vec<(
                uuid::Uuid,
                uuid::Uuid,
                String,
                Option<f64>,
                Option<f64>,
                Option<String>,
            )> = match sqlx::query_as(
                "SELECT t.workflow_id, w.user_id, w.name, \
                            t.success_rate_pct::float8, t.p95_latency_ms::float8, \
                            t.notification_webhook \
                     FROM workflow_sla_thresholds t \
                     JOIN workflows w ON w.id = t.workflow_id \
                     LIMIT 500",
            )
            .fetch_all(&sla_pool)
            .await
            {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::error!("SLA check: failed to fetch thresholds: {}", e);
                    continue;
                }
            };

            for (wf_id, wf_user_id, wf_name, target_rate, target_p95, webhook) in &sla_rows {
                // Use centralized AnalyticsRepository::get_sla_window_stats so
                // SLA alerting and readiness scoring share identical PERCENTILE
                // computations.
                let stats = match analytics_repo.get_sla_window_stats(*wf_id, 24).await {
                    Some(s) if s.total >= 3 => s, // Minimum volume: 3 executions
                    _ => continue,
                };
                let (total, successes, p95_ms) = (stats.total, stats.successes, stats.p95_ms);

                let actual_rate = (successes as f64 / total as f64) * 100.0;

                // Check success rate SLA
                if let Some(target) = target_rate {
                    if actual_rate < *target {
                        let msg = format!(
                            "SLA violation: {} success rate {:.1}% < threshold {:.1}% (last 24h, {}/{})",
                            wf_name, actual_rate, target, successes, total
                        );
                        // Create alert (dedup handles repeated violations).
                        // If the alert insert fails, the next tick won't see
                        // the existing dedup row and would re-insert — log
                        // so the dedup behavior is observable.
                        // N-L (2026-05-06): snapshot workflow_name into the
                        // alert row so the operator dashboard surfaces the
                        // name even after the workflow is deleted.
                        if let Err(e) = sqlx::query(
                            "INSERT INTO workflow_alerts (id, user_id, workflow_id, execution_id, alert_type, message, workflow_name) \
                             VALUES ($1, $2, $3, $4, 'sla_violation', $5, $6) \
                             ON CONFLICT (workflow_id, message) WHERE acknowledged = false \
                             DO UPDATE SET occurrence_count = workflow_alerts.occurrence_count + 1, \
                                          last_occurred_at = NOW()",
                        )
                        .bind(uuid::Uuid::new_v4())
                        .bind(wf_user_id)
                        .bind(wf_id)
                        .bind(uuid::Uuid::nil()) // no specific execution
                        .bind(&msg)
                        .bind(wf_name)
                        .execute(&sla_pool)
                        .await
                        {
                            tracing::error!(
                                workflow_id = %wf_id,
                                error = %e,
                                "SLA monitor: failed to insert/dedup workflow_alert (success-rate)"
                            );
                        }

                        tracing::warn!(workflow = %wf_name, actual = actual_rate, target = target, "SLA violation detected");

                        // Fire notification webhook if configured
                        if let Some(url) = webhook {
                            if !url.is_empty()
                                && mcp::utils::check_outbound_url_no_ssrf(url).is_ok()
                            {
                                let payload = serde_json::json!({
                                    "event": "sla_violation",
                                    "workflow_id": wf_id,
                                    "workflow_name": wf_name,
                                    "metric": "success_rate",
                                    "actual": actual_rate,
                                    "threshold": target,
                                    "period": "24h",
                                    "timestamp": chrono::Utc::now().to_rfc3339()
                                });
                                let client = http_client.clone();
                                let url = url.clone();
                                // MCP-774 (2026-05-13): log delivery failures
                                // on the SLA-degradation webhook fire. Pre-fix
                                // `let _ = ...await` discarded both Ok-status
                                // and Err — if the operator's notification
                                // endpoint (PagerDuty / Slack / incident-mgmt)
                                // was unreachable (DNS / TLS / 5xx / network
                                // partition), the SLA violation was DETECTED
                                // and ALERTED locally (via workflow_alerts
                                // INSERT above) but NEVER delivered, with zero
                                // log signal correlating the delivery failure
                                // to controller health. Same operator-visibility
                                // class as MCP-742 (failure_webhook.rs sibling)
                                // and MCP-733..746. The 5-minute SLA threshold
                                // breach task in this same file (~line 3729 /
                                // 3756) already follows the canonical shape;
                                // this 15-minute degradation task was drifted.
                                tokio::spawn(async move {
                                    match client.post(&url).json(&payload).send().await {
                                        Ok(resp) if resp.status().is_success() => {
                                            tracing::debug!(
                                                webhook = %url,
                                                status = resp.status().as_u16(),
                                                "SLA-degradation webhook delivered"
                                            );
                                        }
                                        Ok(resp) => {
                                            tracing::warn!(
                                                target: "talos_rpc",
                                                webhook = %url,
                                                status = resp.status().as_u16(),
                                                "SLA-degradation webhook returned non-success status — operator notification may not have reached its destination"
                                            );
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                target: "talos_rpc",
                                                webhook = %url,
                                                error = %e,
                                                "SLA-degradation webhook POST failed — operator notification undelivered"
                                            );
                                        }
                                    }
                                });
                            }
                        }
                    }
                }

                // Check p95 latency SLA
                if let (Some(target), Some(actual)) = (target_p95, p95_ms) {
                    if actual > *target {
                        let msg = format!(
                            "SLA violation: {} p95 latency {:.0}ms > threshold {:.0}ms (last 24h)",
                            wf_name, actual, target
                        );
                        // N-L: workflow_name snapshot, see above.
                        if let Err(e) = sqlx::query(
                            "INSERT INTO workflow_alerts (id, user_id, workflow_id, execution_id, alert_type, message, workflow_name) \
                             VALUES ($1, $2, $3, $4, 'sla_violation', $5, $6) \
                             ON CONFLICT (workflow_id, message) WHERE acknowledged = false \
                             DO UPDATE SET occurrence_count = workflow_alerts.occurrence_count + 1, \
                                          last_occurred_at = NOW()",
                        )
                        .bind(uuid::Uuid::new_v4())
                        .bind(wf_user_id)
                        .bind(wf_id)
                        .bind(uuid::Uuid::nil())
                        .bind(&msg)
                        .bind(wf_name)
                        .execute(&sla_pool)
                        .await
                        {
                            tracing::error!(
                                workflow_id = %wf_id,
                                error = %e,
                                "SLA monitor: failed to insert/dedup workflow_alert (p95-latency)"
                            );
                        }
                    }
                }
            }

            // 2. Catch catastrophic failures for workflows WITHOUT explicit thresholds
            // Alert when success rate < 50% with at least 5 executions in the last 24h
            let catastrophic: Vec<(uuid::Uuid, uuid::Uuid, String, i64, i64)> = sqlx::query_as(
                "SELECT w.id, w.user_id, w.name, \
                        COUNT(*), \
                        COUNT(*) FILTER (WHERE we.status = 'completed') \
                 FROM workflows w \
                 JOIN workflow_executions we ON we.workflow_id = w.id \
                 WHERE we.started_at > NOW() - INTERVAL '24 hours' \
                   AND w.status = 'active' \
                   AND w.id NOT IN (SELECT workflow_id FROM workflow_sla_thresholds) \
                 GROUP BY w.id, w.user_id, w.name \
                 HAVING COUNT(*) >= 5 \
                    AND (COUNT(*) FILTER (WHERE we.status = 'completed'))::float / COUNT(*) < 0.5 \
                 LIMIT 100",
            )
            .fetch_all(&sla_pool)
            .await
            .unwrap_or_default();

            for (wf_id, wf_user_id, wf_name, total, successes) in &catastrophic {
                let rate = (*successes as f64 / *total as f64) * 100.0;
                let msg = format!(
                    "Catastrophic failure rate: {} at {:.1}% success ({}/{} in 24h). \
                     Set an SLA threshold with set_workflow_sla_threshold to customize alerting.",
                    wf_name, rate, successes, total
                );
                if let Err(e) = sqlx::query(
                    "INSERT INTO workflow_alerts (id, user_id, workflow_id, execution_id, alert_type, message) \
                     VALUES ($1, $2, $3, $4, 'catastrophic_failure_rate', $5) \
                     ON CONFLICT (workflow_id, message) WHERE acknowledged = false \
                     DO UPDATE SET occurrence_count = workflow_alerts.occurrence_count + 1, \
                                  last_occurred_at = NOW()",
                )
                .bind(uuid::Uuid::new_v4())
                .bind(wf_user_id)
                .bind(wf_id)
                .bind(uuid::Uuid::nil())
                .bind(&msg)
                .execute(&sla_pool)
                .await
                {
                    tracing::error!(
                        workflow_id = %wf_id,
                        error = %e,
                        "SLA monitor: failed to insert/dedup workflow_alert (catastrophic-failure)"
                    );
                }

                tracing::warn!(workflow = %wf_name, success_rate = rate, "Catastrophic failure rate detected");
            }
        }
    });
    tracing::info!("SLA degradation alerting task started (runs every 15 minutes)");
}

/// Gmail watch renewal, Google Calendar channel renewal, and the OAuth
/// proactive token refresh loops. Extracted verbatim from `main()`; spawn
/// order preserved.
fn spawn_integration_renewal_tasks(
    services: &PlatformServices,
    bg_shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let gmail_watch_service = services.gmail_watch_service.clone();
    let google_calendar_service = services.google_calendar_service.clone();
    let oauth_credential_service = services.oauth_credential_service.clone();
    // ---------- Start Gmail watch renewal task ----------
    if let Some(ref gmail_watch) = gmail_watch_service {
        let renewal = gmail_watch.clone();
        let gmail_renewal_shutdown = bg_shutdown_rx.clone();
        tokio::spawn(async move {
            gmail::scheduler::gmail_renewal_task(renewal, gmail_renewal_shutdown).await;
        });
        tracing::info!("Gmail watch renewal task started (runs every hour)");

        // Sweep the per-(user,integration) create-lock map hourly so
        // it doesn't grow unbounded in a long-running controller.
        let cleanup_gmail = gmail_watch.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                cleanup_gmail.cleanup_create_locks();
            }
        });
    }

    // ---------- GCP watch create-lock sweep ----------
    // No renewal task for GCP (the user owns the upstream subscription;
    // nothing on our side expires). We only sweep the create-lock map so
    // it can't grow unbounded over the controller's lifetime.
    if let Some(gcp_watch) = services.gcp_watch_service.clone() {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                gcp_watch.cleanup_create_locks();
            }
        });
    }

    // ---------- Start Google Calendar channel renewal task ----------
    if google_calendar_service.is_configured() {
        let renewal_service = google_calendar_service.clone();
        let gcal_renewal_shutdown = bg_shutdown_rx.clone();
        tokio::spawn(async move {
            google_calendar::scheduler::channel_renewal_task(
                renewal_service,
                gcal_renewal_shutdown,
            )
            .await;
        });
        tracing::info!("Google Calendar channel renewal task started (runs every hour)");

        // Per-channel webhook rate-limiter cleanup (runs every 5 minutes).
        // Also sweeps the create_channel_locks DashMap to prevent
        // unbounded growth over the controller's lifetime.
        let cleanup_gcal_rl = google_calendar_service.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                cleanup_gcal_rl.cleanup_webhook_channel_limits();
                cleanup_gcal_rl.cleanup_create_channel_locks();
            }
        });

        // Event sync task will be started after Redis/NATS are initialized
    }

    // ---------- Start OAuth proactive token refresh task ----------
    {
        let cred_service_bg = oauth_credential_service.clone();
        tokio::spawn(async move {
            oauth::refresh_task::proactive_token_refresh_task(cred_service_bg).await;
        });
        tracing::info!("OAuth proactive token refresh task started (5-minute interval)");
    }
}

/// WASM-log subscriber + job-result subscriber (both supervisor-wrapped,
/// MCP-1121/1122). Extracted verbatim from `main()`; spawn order preserved.
fn spawn_nats_log_subscribers(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    nats_client: Option<std::sync::Arc<async_nats::Client>>,
    services: &PlatformServices,
    buses: &EventBuses,
) -> anyhow::Result<()> {
    let module_execution_service = services.module_execution_service.clone();
    let worker_shared_key = services.worker_shared_key.clone();
    let tx = buses.tx.clone();
    let workflow_execution_tx = buses.workflow_execution_tx.clone();
    // ---------- Start WASM log subscriber (automatic logging from worker) ----------
    // This background task receives logs from WASM executions and persists them to database
    // Provides guaranteed observability for all WASM module executions
    if let Some(nats) = nats_client.clone() {
        let exec_service_for_logs = module_execution_service.clone();
        let tx_for_wasm_logs = tx.clone();
        // Build a lightweight ExecutionRepository for the wasm-log subscriber
        // so it can persist workflow-execution logs to the new
        // workflow_execution_logs table. Output encryption isn't needed —
        // the subscriber only writes logs, never reads encrypted outputs.
        let exec_repo_for_wasm_logs = std::sync::Arc::new(
            crate::execution_repository::ExecutionRepository::new(db_pool.clone())
                .with_workflow_execution_sender(workflow_execution_tx.clone()),
        );
        tokio::spawn(async move {
            tracing::info!("Starting WASM log subscriber on topic: wasm.log.*");

            // MCP-1121 (2026-05-16): supervisor loop wraps the inner
            // subscriber. Sibling sweep of MCP-1119/1120 (audit-ledger
            // JetStream + worker-fleet heartbeats). Pre-fix when
            // `subscriber.next()` returned None (NATS disconnect,
            // server-side unsubscribe, client reconnect window), the
            // spawned task exited and workflow execution logs stopped
            // persisting until controller restart — `workflow_execution_logs`
            // table received nothing, the UI's live log stream went
            // silent, and operators couldn't see workflow progress
            // mid-execution. Workers continue publishing to NATS but
            // without a JetStream durable here the messages drop on
            // the floor.
            //
            // Same audit rule (MCP-1119/1120): every background-spawned
            // message-consumer that processes external infrastructure
            // events MUST be supervisor-wrapped. Exponential backoff
            // caps at 60s, resets on successful bind.
            let mut backoff_secs: u64 = 1;
            'supervisor: loop {
                // Subscribe to all WASM log topics (wasm.log.{execution_id})
                let mut subscriber = match nats.subscribe("wasm.log.*").await {
                    Ok(sub) => sub,
                    Err(e) => {
                        tracing::error!(
                            target: "talos_controller",
                            event_kind = "wasm_log_subscribe_failed",
                            error = %e,
                            backoff_secs,
                            "Failed to subscribe to WASM logs; retrying after backoff"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(60);
                        continue 'supervisor;
                    }
                };
                backoff_secs = 1;

                tracing::info!("WASM log subscriber active - waiting for messages");

                // Process messages as they arrive
                while let Some(msg) = subscriber.next().await {
                    // DEBUG: Log when message is received
                    tracing::info!("📩 Received WASM log from NATS topic: {}", msg.subject);

                    // Parse log message from NATS
                    match serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                        Ok(log_msg) => {
                            // Extract fields with defaults
                            let execution_id = log_msg
                                .get("execution_id")
                                .and_then(|v| v.as_str())
                                .and_then(|s| uuid::Uuid::parse_str(s).ok());

                            let level_str = log_msg
                                .get("level")
                                .and_then(|v| v.as_str())
                                .unwrap_or("info");

                            // Convert string to LogLevel enum. Case-insensitive
                            // because the worker emits UPPERCASE ("INFO", "WARN",
                            // ...) while older test paths used lowercase. Without
                            // the fold, every uppercase line collapsed to Info.
                            let level = match level_str.to_ascii_lowercase().as_str() {
                                "debug" => LogLevel::Debug,
                                "warn" => LogLevel::Warn,
                                "error" => LogLevel::Error,
                                _ => LogLevel::Info,
                            };

                            let message = log_msg
                                .get("message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();

                            let metadata = log_msg.get("metadata").cloned();
                            let trace_id = log_msg
                                .get("trace_id")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            let span_id = log_msg
                                .get("span_id")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());

                            // Save to database (best-effort - don't crash on error)
                            if let Some(exec_id) = execution_id {
                                let node_id = metadata
                                    .as_ref()
                                    .and_then(|m| m.get("node_id"))
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| uuid::Uuid::parse_str(s).ok());

                                // MCP-1011 sibling: scrub the broadcast `message`
                                // the same way `add_workflow_log` scrubs before
                                // persisting. Pre-fix the persistence path
                                // (`workflow_execution_logs.message`) applied
                                // MCP-481 truncation + control-char strip +
                                // `redact_str`, but the parallel `tx_for_wasm_logs`
                                // broadcast used the raw `message` — a WASM module
                                // emitting a Bearer / sk- / ghp_ token leaked it
                                // to live `execution_updates` GraphQL subscribers
                                // even though the persisted row was clean. See
                                // `scrub_wasm_log_for_broadcast` (above) for the
                                // canonical pipeline — kept in lockstep with the
                                // persistence path so the live channel can't
                                // carry more than the persisted row.
                                let scrubbed_for_broadcast = scrub_wasm_log_for_broadcast(&message);

                                // Broadcast the live log to all connected GraphQL clients!
                                let _ = tx_for_wasm_logs.send(ExecutionEvent {
                                    execution_id: exec_id,
                                    node_id,
                                    status: ExecutionStatus::Running,
                                    trace_id,
                                    span_id,
                                    log_message: Some(format!(
                                        "[{}] {}",
                                        level_str.to_uppercase(),
                                        scrubbed_for_broadcast
                                    )),
                                    iteration_index: None,
                                    iteration_total: None,
                                    duration_ms: None,
                                    output: None,
                                });

                                // Route to the right log table:
                                //   - workflow_execution_logs when exec_id is a workflow_executions.id
                                //     (the common case — every run via trigger_workflow / call_workflow / scheduled)
                                //   - module_execution_logs when exec_id is a module_executions.id
                                //     (standalone module runs via webhook / test_module)
                                // `add_workflow_log` does a `WHERE EXISTS`-guarded insert and
                                // returns `Ok(false)` (rather than tripping the FK constraint)
                                // when exec_id isn't a workflow execution — so the standalone-
                                // module case no longer emits a Postgres FK-violation ERROR per
                                // log line. Single round trip for the common (workflow) case.
                                let level_upper = match level {
                                    LogLevel::Debug => "DEBUG",
                                    LogLevel::Info => "INFO",
                                    LogLevel::Warn => "WARN",
                                    LogLevel::Error => "ERROR",
                                };
                                match exec_repo_for_wasm_logs
                                    .add_workflow_log(
                                        exec_id,
                                        node_id,
                                        level_upper,
                                        &message,
                                        metadata.as_ref(),
                                    )
                                    .await
                                {
                                    Ok(true) => {} // landed in workflow_execution_logs
                                    Ok(false) => {
                                        // Not a workflow execution → standalone module run.
                                        exec_service_for_logs
                                            .add_log_best_effort(exec_id, level, message, metadata)
                                            .await;
                                    }
                                    Err(e) => {
                                        // exec_id IS a workflow execution but the insert failed
                                        // (5000-entry rate-limit trigger, DB outage). Don't
                                        // misroute a real workflow log to the module table.
                                        tracing::debug!(
                                            %exec_id,
                                            error = %e,
                                            "workflow_execution_logs insert failed (capped or DB error)"
                                        );
                                    }
                                }
                            } else {
                                tracing::debug!("Received WASM log without valid execution_id");
                            }
                        }
                        Err(e) => {
                            tracing::debug!("Failed to parse WASM log message: {}", e);
                        }
                    }
                }

                // MCP-1121: stream ended — supervisor re-binds.
                tracing::warn!(
                    target: "talos_controller",
                    event_kind = "wasm_log_subscriber_rebinding",
                    "WASM log subscriber stream ended; supervisor re-binding (no controller restart required)"
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            } // end 'supervisor
        });
        tracing::info!("WASM log subscriber task started");

        // ---------- Start job result subscriber ----------
        // The worker publishes JobResult messages to talos.results.{job_id} after each
        // WASM execution completes.  This subscriber receives those results and updates
        // the module_executions record status to 'completed' or 'failed' so the UI can
        // display the outcome.
        let exec_service_for_results = module_execution_service.clone();
        let nats_for_results = nats_client
            .clone()
            .ok_or_else(|| anyhow::anyhow!("NATS client missing"))?;
        // Clone the shared key into a verify-ring (current + any staged
        // WORKER_SHARED_KEY_PREVIOUS) so this audit observer accepts results
        // signed under a previous key during a rolling rotation, consistent
        // with the primary verifier in the engine dispatcher. Moved into the
        // spawn; the original `worker_shared_key` is still used later for the
        // Extension layer.
        let worker_key_ring_for_results = worker_shared_key.clone().map(|signing| {
            talos_workflow_engine_core::WorkerKeyRing::new(
                signing,
                talos_workflow_job_protocol::load_worker_shared_key_previous().unwrap_or_default(),
            )
        });
        tokio::spawn(async move {
            tracing::info!("Starting job result subscriber on topic: talos.results.*");

            // MCP-1122 (2026-05-16): supervisor loop wraps the inner
            // subscriber. Fourth site in the MCP-1119/1120/1121 sweep.
            // The comment further down at line ~2960 notes this
            // subscriber is "mostly dormant" today (every NATS-dispatched
            // path uses request-reply), but it's the canonical landing
            // point for future async-dispatch / work-queue patterns —
            // when those land, the subscriber silently exiting on
            // stream-end (NATS reconnect, server-side unsubscribe,
            // client reconnect window) would be a latent reliability
            // gap. Bring it into supervisor parity with siblings now
            // so a future regression doesn't surface as "results
            // mysteriously stopped updating after a NATS hiccup."
            let mut backoff_secs: u64 = 1;
            'supervisor: loop {
                let mut sub = match nats_for_results.subscribe("talos.results.*").await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(
                            target: "talos_controller",
                            event_kind = "job_result_subscribe_failed",
                            error = %e,
                            backoff_secs,
                            "Failed to subscribe to job results; retrying after backoff"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(60);
                        continue 'supervisor;
                    }
                };
                backoff_secs = 1;

                tracing::info!("Job result subscriber active");

                while let Some(msg) = sub.next().await {
                    match serde_json::from_slice::<talos_workflow_job_protocol::JobResult>(
                        &msg.payload,
                    ) {
                        Ok(result) => {
                            let job_id = result.job_id;

                            // SECURITY: Verify HMAC-SHA256 signature + freshness
                            // window. Rejects results injected by any process that
                            // can publish to NATS but does not know the pre-shared
                            // key.
                            //
                            // Post-r301 the worker single-publishes: it sends a
                            // result to EITHER the request-reply inbox OR
                            // `talos.results.{job_id}` based on whether the
                            // requester awaited the reply, never both. So this
                            // subscriber only sees results that no other in-process
                            // verifier has handled — there's no second verify to
                            // race.
                            //
                            // We still call `verify_no_replay` here (not `verify`)
                            // as defense-in-depth: it keeps this subscriber
                            // safe-by-default if a future code path re-introduces a
                            // dual-publish or a sibling subscriber, and the side
                            // effect (`UPDATE module_executions WHERE status IN
                            // ('pending','running')`) is idempotent under replay
                            // anyway. HMAC + freshness still catch forgery and
                            // stale-replay; the worker is the primary
                            // replay-cache writer for fire-and-forget results.
                            //
                            // Today every NATS-dispatched code path uses
                            // request-reply, so this subscriber is mostly dormant
                            // — kept as the canonical landing point for future
                            // truly-async dispatches (work-queue style).
                            // L-4: typed Observer verifier — this audit
                            // subscriber on `talos.results.*` only writes
                            // an idempotent UPDATE; primary verification
                            // happens at the request-reply inbox in the
                            // engine dispatcher / webhook handler. Using
                            // `Verifier::Observer` documents the role at
                            // the type level so a future refactor can't
                            // accidentally convert this site to a primary
                            // verifier and reintroduce the r300 regression.
                            if let Some(ref ring) = worker_key_ring_for_results {
                                // RFC 0010 P2: scheme-routing Observer verify —
                                // Ed25519 against the keys registered for this
                                // worker_id, or legacy HMAC against the ring
                                // while `result_accept_legacy_hmac()`. NEVER
                                // records the replay cache (Observer role): the
                                // request-reply dispatcher is the sole Primary
                                // verifier, per the verify-once rule.
                                let worker_ed_keys =
                                    talos_workflow_job_protocol::worker_public_keys(
                                        &result.worker_id,
                                    );
                                if let Err(e) = result.verify_no_replay_dispatch(
                                    ring,
                                    &worker_ed_keys,
                                    300,
                                    talos_workflow_job_protocol::result_accept_legacy_hmac(),
                                ) {
                                    tracing::warn!(
                                    "Rejected job result {}: signature verification failed — {}",
                                    job_id,
                                    e
                                );
                                    continue;
                                }
                            }
                            tracing::debug!(
                                "📥 Received job result: {} ({:?}, {}ms)",
                                job_id,
                                result.status,
                                result.execution_time_ms
                            );

                            match result.status {
                                talos_workflow_job_protocol::JobStatus::Success => {
                                    if let Err(e) = exec_service_for_results
                                        .complete_execution_from_worker(
                                            job_id,
                                            Some(result.output_payload),
                                        )
                                        .await
                                    {
                                        tracing::warn!(
                                            "Failed to mark execution {} as completed: {}",
                                            job_id,
                                            e
                                        );
                                    } else {
                                        tracing::info!(
                                            "✅ Execution {} completed ({}ms)",
                                            job_id,
                                            result.execution_time_ms
                                        );
                                    }
                                }
                                talos_workflow_job_protocol::JobStatus::Failed
                                | talos_workflow_job_protocol::JobStatus::TimedOut => {
                                    let error_msg = result
                                        .output_payload
                                        .get("error")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("Worker reported failure")
                                        .to_string();
                                    let error_type = matches!(
                                        result.status,
                                        talos_workflow_job_protocol::JobStatus::TimedOut
                                    )
                                    .then_some("timeout".to_string());

                                    if let Err(e) = exec_service_for_results
                                        .fail_execution_from_worker(
                                            job_id,
                                            error_msg.clone(),
                                            error_type,
                                        )
                                        .await
                                    {
                                        tracing::warn!(
                                            "Failed to mark execution {} as failed: {}",
                                            job_id,
                                            e
                                        );
                                    } else {
                                        // MCP-989 (2026-05-15): DLP-redact the
                                        // failure preview at the operator-log
                                        // boundary. `fail_execution_from_worker`
                                        // redacts before persisting to
                                        // `module_executions.error_message`
                                        // (MCP-968), but this INFO log was
                                        // taking the first 100 chars of the
                                        // ORIGINAL worker-supplied error_msg.
                                        // Worker failures regularly carry
                                        // upstream auth errors that echo the
                                        // rejected token in the body; secret-
                                        // shaped prefixes must not land in
                                        // operator log pipelines. Same
                                        // wrapper class as the two
                                        // talos-module-executions sites
                                        // closed in this MCP.
                                        let preview: String =
                                            talos_dlp_provider::redact_str(&error_msg)
                                                .chars()
                                                .take(100)
                                                .collect();
                                        tracing::info!(
                                            "❌ Execution {} failed: {}",
                                            job_id,
                                            preview
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!("Failed to parse job result message: {}", e);
                        }
                    }
                }

                // MCP-1122: stream ended — supervisor re-binds.
                tracing::warn!(
                    target: "talos_controller",
                    event_kind = "job_result_subscriber_rebinding",
                    "Job result subscriber stream ended; supervisor re-binding"
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            } // end 'supervisor
        });
        tracing::info!("Job result subscriber task started");
    } else {
        tracing::warn!("NATS not configured - WASM automatic logging disabled");
    }

    // Note: Periodic event sync task removed — sync_channel_events() advances the sync
    // token each time it runs, which would silently consume the token before the webhook
    // handler could use it, causing missed events. Syncing is driven exclusively by
    // real-time push notifications (webhook_notification_handler).

    Ok(())
}

/// Build the shared TalosRuntime, LLM client, repositories, cross-protocol
/// services, and the GraphQL schema. Extracted verbatim from `main()`. The
/// ExecutionOrchestrationService construction chains
/// `.with_event_sender(tx.clone())` — preserved exactly.
fn build_schema_and_services(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    redis_client: Option<std::sync::Arc<redis::Client>>,
    nats_client: Option<std::sync::Arc<async_nats::Client>>,
    buses: &EventBuses,
    core: &CoreServices,
    services: &PlatformServices,
    actor_repo: std::sync::Arc<actor_repository::ActorRepository>,
) -> anyhow::Result<SchemaBundle> {
    let secrets_manager = core.secrets_manager.clone();
    let registry = core.registry.clone();
    let compiler = core.compiler.clone();
    let compilation_event_tx = core.compilation_event_tx.clone();
    let tx = buses.tx.clone();
    let dlq_tx = buses.dlq_tx.clone();
    let workflow_execution_tx = buses.workflow_execution_tx.clone();
    let worker_shared_key = services.worker_shared_key.clone();
    let worker_manager = services.worker_manager.clone();
    let dlp_service = services.dlp_service.clone();
    let webhook_router = services.webhook_router.clone();
    let auth_service = services.auth_service.clone();
    let totp_service = services.totp_service.clone();
    let api_key_service = services.api_key_service.clone();
    let oauth_service = services.oauth_service.clone();
    let google_calendar_service = services.google_calendar_service.clone();
    let oauth_credential_service = services.oauth_credential_service.clone();
    let gmail_integration_service = services.gmail_integration_service.clone();
    let module_execution_service = services.module_execution_service.clone();
    let auth_rate_limiter = services.auth_rate_limiter.clone();
    // ---------- Build GraphQL schema ----------
    // Shared TalosRuntime with Redis, NATS, and file sandbox support (thread‑safe via Arc)
    // Note: the controller embeds its own WasmRuntime (used by
    // run_sandbox / compile_custom_sandbox). Same `with_resources`
    // signature as the worker — db_pool removed Phase 2.10. The
    // controller's runtime is for in-process sandbox execution
    // (linting, ad-hoc test runs) and routes data ops through the
    // same NATS-RPC subscribers it serves.
    let runtime = std::sync::Arc::new(TalosRuntime::with_resources(
        redis_client.clone(),
        nats_client.clone(),
        None, // File sandbox configured per-execution
    )?);
    // Initialize the shared LLM client.
    //
    // Vault-backed so per-request key resolution hits `SecretsManager::
    // get_llm_vault_keys` (60s cache, eager invalidation on rotate_secret).
    // The env var acts as a bootstrap fallback for fresh deploys before
    // the vault has a key; it's NOT the source of truth post-bootstrap.
    //
    // A single Arc is built here and shared by both the GraphQL schema
    // context and the MCP state — the previous code constructed two
    // independent clients from the same env var, which silently diverged
    // if the env was mutated between the two reads.
    let anthropic_env_fallback = std::env::var("ANTHROPIC_API_KEY")
        .ok()
        .filter(|v| !v.is_empty());
    let llm_client: Option<std::sync::Arc<crate::llm::LlmClient>> = Some(std::sync::Arc::new(
        crate::llm::LlmClient::with_vault(secrets_manager.clone(), anthropic_env_fallback.clone()),
    ));

    // Repositories the GraphQL schema needs to share with the MCP
    // router. Pre-spike these were constructed late (just before
    // create_router); hoisted here so the schema can wire them as
    // ctx.data and consume the same shared service instances. The
    // WorkflowCreationService below is the first cross-protocol
    // consumer — see GraphQL `createWorkflowFromDescription` and MCP
    // `handle_create_workflow_from_description`.
    // N T5-N1: wire SecretsManager so `mark_execution_*` and
    // `update_execution_output` encrypt `output_data` at rest, matching
    // the symmetry already in `ExecutionRepository` and
    // `ActorRepository::complete_execution`.
    let workflow_repo = std::sync::Arc::new(
        workflow_repository::WorkflowRepository::new(db_pool.clone())
            .with_encryption(secrets_manager.clone())
            .with_workflow_execution_sender(workflow_execution_tx.clone()),
    );
    let module_repo = std::sync::Arc::new(
        module_repository::ModuleRepository::new(db_pool.clone())
            .with_encryption(secrets_manager.clone()),
    );
    // Hoisted up from the late create_router construction site so
    // the ExecutionOrchestrationService below (which consumes both)
    // can share the same instances with both the GraphQL schema and
    // the MCP router. Cheap construction.
    let execution_repo = std::sync::Arc::new(
        crate::execution_repository::ExecutionRepository::with_encryption(
            db_pool.clone(),
            secrets_manager.clone(),
        )
        .with_workflow_execution_sender(workflow_execution_tx.clone()),
    );
    // `actor_repo` was built earlier (before the Graph RAG init
    // block) so it could be handed into `GraphRagService` for the
    // tier-1 data-egress gate. Reused here without rebuilding.

    // Pre-build the workflow-creation service so GraphQL and MCP
    // share one instance (one DEK cache, one LLM-client clone, one
    // template registry view). Cheap construction — just stores
    // injected Arcs.
    let workflow_creation_service =
        std::sync::Arc::new(talos_workflow_creation::WorkflowCreationService::new(
            workflow_repo.clone(),
            llm_client.clone(),
            dlp_service.clone(),
            module_repo.clone(),
            compiler.clone(),
        ));

    // Hot-update orchestration. Single shared instance — the recompile
    // path is otherwise the same logic for MCP and (future) GraphQL.
    let hot_update_service = std::sync::Arc::new(talos_hot_update_service::HotUpdateService::new(
        module_repo.clone(),
        workflow_repo.clone(),
        compiler.clone(),
        db_pool.clone(),
    ));

    // Execution-orchestration service. Single shared instance backs
    // the MCP trigger/replay/retry handlers AND the GraphQL
    // `triggerWorkflow` mutation; both protocols pull the same Arc
    // from their respective contexts so the engine builder, NATS
    // dispatch, and auth gate are identical regardless of how the
    // call entered the controller.
    let execution_orchestration_service = std::sync::Arc::new(
        talos_execution_orchestration::ExecutionOrchestrationService::new(
            workflow_repo.clone(),
            execution_repo.clone(),
            actor_repo.clone(),
            secrets_manager.clone(),
            registry.clone(),
            nats_client.clone(),
            worker_shared_key.clone(),
            db_pool.clone(),
        )
        // Live executionUpdates events for terminal transitions — with the
        // service owning emission, MCP-triggered executions broadcast the
        // same events GraphQL-triggered ones do (pre-2026-07-01 only the
        // GraphQL-inline trigger path fed the channel).
        .with_event_sender(tx.clone()),
    );

    // Workflow-manifest service. Single shared instance backs the MCP
    // import_platform_state / export_platform_state tools and is ready
    // to back a future GraphQL surface without protocol branching.
    let workflow_manifest_service =
        std::sync::Arc::new(talos_workflow_manifest::WorkflowManifestService::new(
            workflow_repo.clone(),
            module_repo.clone(),
            secrets_manager.clone(),
        ));

    // Replay service. Single shared instance backs the MCP
    // replay_module_regression handler (both module and workflow
    // modes) and is ready to back a future GraphQL surface — typed
    // input + outcome, ReplayError carries a stable jsonrpc_code()
    // mapping so the protocol wrapper stays trivial.
    let replay_service = std::sync::Arc::new(talos_replay_service::ReplayService::new(
        registry.clone(),
        workflow_repo.clone(),
        module_repo.clone(),
        // MCP-691 (2026-05-13): actor_repo is used by resolve_replay_tier
        // to look up the workflow's actor and inherit its max_llm_tier
        // ceiling for replay — closes a Tier-1 leak surface where
        // replays defaulted to Tier-2.
        actor_repo.clone(),
        secrets_manager.clone(),
        runtime.clone(),
    ));

    // Inline-Rust compile service. Single shared instance backs the
    // `rust_code` branch of `add_node_to_workflow` (and is ready to
    // back any future protocol surface — same Arc → same wrap-lint-
    // compile-mirror flow). Owns the shared-module-overwrite +
    // permission-drift guards that were inline in workflows.rs.
    let inline_compile_service =
        std::sync::Arc::new(talos_inline_compile_service::InlineCompileService::new(
            workflow_repo.clone(),
            module_repo.clone(),
            compiler.clone(),
            db_pool.clone(),
        ));

    // Search service. Owns the semantic-search fallback chain
    // (caller embedding → auto-generate → vector → trigram → ILIKE)
    // plus the embedding pipeline (config, rate-limited generator,
    // provider health probe). Embedding primitives are exported as
    // free functions on the crate; the service struct composes them
    // with WorkflowRepository SQL helpers for the chain orchestration.
    let search_service = std::sync::Arc::new(talos_search_service::SearchService::new(
        workflow_repo.clone(),
    ));

    // Failure-analysis service. Backs the MCP `analyze_execution_failure`
    // tool — per-node error classification + remediation playbooks + the
    // config-field auto-fix write path — and is ready to back a future
    // GraphQL surface. Typed input + outcome, `FailureAnalysisError`
    // carries a stable jsonrpc_code() mapping.
    let failure_analysis_service = std::sync::Arc::new(
        talos_failure_analysis_service::FailureAnalysisService::new(execution_repo.clone()),
    );

    // Actor-lifecycle service. Backs the MCP `scaffold_actor` and
    // `handoff_to_actor` tools — scaffold arg-validation + orchestration
    // delegation, and the full handoff gate sequence (status / chain /
    // budget / authorization) + engine dispatch. Same Arc is ready for a
    // future GraphQL surface.
    let actor_lifecycle_service =
        std::sync::Arc::new(talos_actor_lifecycle_service::ActorLifecycleService::new(
            db_pool.clone(),
            registry.clone(),
            actor_repo.clone(),
            workflow_repo.clone(),
            module_repo.clone(),
            secrets_manager.clone(),
            nats_client.clone(),
        ));

    // Build async-graphql schema with limits (defense in depth)
    let mut schema_builder = Schema::build(
        QueryRoot::default(),
        MutationRoot::default(),
        SubscriptionRoot,
    )
    // Security limits to prevent DoS attacks via expensive queries
    .limit_depth(15) // Maximum query nesting depth
    .limit_complexity(5000); // Maximum query complexity score

    // Disable GraphQL introspection in production to prevent schema enumeration.
    if config::is_production() {
        schema_builder = schema_builder.disable_introspection();
        tracing::info!("GraphQL introspection disabled (production mode)");
    }

    let schema_builder = schema_builder
        .data(tx)
        .data(runtime.clone())
        .data(db_pool.clone())
        .data(registry.clone())
        .data(compiler.clone())
        .data(secrets_manager.clone())
        .data(webhook_router.clone())
        .data(auth_service.clone())
        .data(totp_service)
        .data(api_key_service.clone())
        .data(oauth_service.clone())
        .data(google_calendar_service.clone())
        // Generic OAuth credential service — used by oauthIntegrations query,
        // connectOAuthIntegration, and disconnectOAuthIntegration mutations.
        .data(oauth_credential_service.clone())
        // Gmail integration service — used by connectOAuthIntegration (provider="gmail").
        .data(gmail_integration_service.clone())
        .data(module_execution_service.clone())
        .data(worker_shared_key.clone())
        .data(worker_manager.clone())
        .data(async_graphql::dataloader::DataLoader::new(
            crate::api::schema::ModuleLoader(db_pool.clone()),
            tokio::spawn,
        ))
        .data(async_graphql::dataloader::DataLoader::new(
            crate::api::schema::ModuleExecutionLogLoader(module_execution_service.clone()),
            tokio::spawn,
        ))
        .data(nats_client.clone())
        .data(dlq_tx.clone())
        .data(workflow_execution_tx.clone())
        .data(compilation_event_tx.clone())
        .data(auth_rate_limiter.clone())
        // Workflow-creation service. First service shared verbatim
        // between the GraphQL surface (createWorkflowFromDescription
        // mutation) and the MCP surface (handle_create_workflow_from_description).
        .data(workflow_creation_service.clone())
        // Execution-orchestration service. Same instance shared with
        // MCP — the `triggerWorkflow` GraphQL mutation extracts this
        // Arc from context and calls `service.trigger(input)`.
        .data(execution_orchestration_service.clone());

    // GraphQL resolvers look up `ctx.data::<LlmClient>()` — pass a Clone of
    // the inner value. The Arc stays behind for the MCP state below.
    let schema = if let Some(ref llm) = llm_client {
        schema_builder.data((**llm).clone()).finish()
    } else {
        schema_builder.finish()
    };

    Ok(SchemaBundle {
        schema,
        runtime,
        llm_client,
        workflow_repo,
        module_repo,
        execution_repo,
        workflow_creation_service,
        hot_update_service,
        execution_orchestration_service,
        workflow_manifest_service,
        replay_service,
        inline_compile_service,
        search_service,
        failure_analysis_service,
        actor_lifecycle_service,
    })
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

/// Stale-execution cleanup, the workflow scheduler, and the SLA threshold
/// breach check. Extracted verbatim from `main()`; spawn order preserved
/// (these three started after router assembly in the original body).
fn spawn_late_background_tasks(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    nats_client: Option<std::sync::Arc<async_nats::Client>>,
    core: &CoreServices,
    services: &PlatformServices,
    tx_for_scheduler: broadcast::Sender<ExecutionEvent>,
    bg_shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let secrets_manager = core.secrets_manager.clone();
    let registry = core.registry.clone();
    let worker_manager = services.worker_manager.clone();
    let module_execution_service = services.module_execution_service.clone();
    let worker_shared_key = services.worker_shared_key.clone();
    // ---------- Start stale execution cleanup task ----------
    // Marks executions stuck in 'running' state beyond a configurable threshold
    // as 'failed'. Prevents ghost executions from accumulating indefinitely.
    //
    // MCP-1042 (2026-05-15): subscribe to `bg_shutdown_rx` so SIGTERM
    // exits the loop cleanly between ticks instead of aborting the
    // task (and any in-flight UPDATE) when the tokio runtime drops at
    // process end. Sibling discipline to the LLM-keys cache sweep
    // (line 1075) and the actor-memory TTL sweep — DB-writing
    // background loops need explicit shutdown wiring to avoid
    // wedging a connection-pool entry on a half-issued statement.
    let cleanup_pool = db_pool.clone();
    let cleanup_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = cleanup_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // MCP-665 (2026-05-13): route through `positive_env_or_default`
                    // so `STALE_EXECUTION_MINUTES=0` doesn't mass-fail every
                    // in-flight execution on the next tick. With `=0`,
                    // `make_interval(mins => 0)` is zero, so
                    // `started_at < NOW() - 0` matches every running row →
                    // catastrophic auto-cleanup that terminates every workflow.
                    // Negative values are equally destructive (NOW() - negative =
                    // future time, also matches everything). Same `=0` footgun
                    // class as MCP-638/643/661/663/664 — this one's the highest-
                    // blast-radius of the set (mass execution kill).
                    let stale_minutes: i32 =
                        talos_config::positive_env_or_default("STALE_EXECUTION_MINUTES", 60i32);
                    let result = sqlx::query(
                        "UPDATE workflow_executions SET status = 'failed', \
                         error_message = 'Auto-cleaned: execution stale (running > configured threshold)', \
                         completed_at = NOW() \
                         WHERE status IN ('running') AND status != 'queued' AND started_at < NOW() - make_interval(mins => $1::int)"
                    ).bind(stale_minutes).execute(&cleanup_pool).await;
                    if let Ok(r) = result {
                        if r.rows_affected() > 0 {
                            tracing::info!(count = r.rows_affected(), "Auto-cleaned stale executions");
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("Stale execution cleanup loop received shutdown signal");
                        break;
                    }
                }
            }
        }
    });
    tracing::info!("Stale execution auto-cleanup task started (runs every 5 minutes, threshold configurable via STALE_EXECUTION_MINUTES)");

    // ---------- Start workflow scheduler ----------
    // Polls every 15 seconds for due schedules and triggers workflow executions.
    // Requires NATS (already required by WebhookRouter, so always available if server started).
    if let Some(nats) = nats_client.clone() {
        let scheduler = std::sync::Arc::new(crate::scheduler::SchedulerService::new(
            db_pool.clone(),
            tx_for_scheduler,
            registry.clone(),
            secrets_manager.clone(),
            worker_manager.clone(),
            module_execution_service.clone(),
            worker_shared_key.clone(),
            nats,
        ));
        let scheduler_shutdown = bg_shutdown_rx.clone();
        tokio::spawn(async move {
            scheduler.run_with_shutdown(scheduler_shutdown).await;
        });
        tracing::info!("Workflow scheduler started (polls every 15 seconds, backfills null next_trigger_at on startup; graceful-shutdown enabled)");
    } else {
        tracing::warn!(
            "Workflow scheduler not started: NATS_URL not configured. \
             Scheduled workflows will not fire automatically."
        );
    }

    // ---------- Start SLA threshold breach check task (Round 43) ----------
    // MCP-1045: subscribe to bg_shutdown_rx — issues per-threshold
    // INSERTs into workflow_sla_alerts on breach detection. Outer
    // 5-min ticker gated; inner per-threshold INSERT runs to natural
    // completion within one tick.
    let sla_pool = db_pool.clone();
    let sla_breach_shutdown = bg_shutdown_rx.clone();
    tokio::spawn(async move {
        let mut shutdown = sla_breach_shutdown;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Every 5 min
                                                                                       // MCP-497: same SSRF-via-redirect fix as MCP-469/470 — the
                                                                                       // `check_outbound_url_no_ssrf` gate below catches the literal
                                                                                       // URL but a 302 from the validated host to an internal host
                                                                                       // bypasses it if reqwest's default redirect policy is in
                                                                                       // effect. `Client::default()` (the prior fallback) re-enables
                                                                                       // following up to 10 hops, so a build-time TLS failure here
                                                                                       // silently reopened the SSRF gap. `.expect()` makes the
                                                                                       // failure loud at startup; `.redirect(Policy::none())` makes
                                                                                       // the SSRF re-check load-bearing.
                                                                                       // MCP-1034: explicit connect_timeout — fast-fail on black-holed
                                                                                       // SLA-alert endpoint.
                                                                                       // Built via the shared SSRF-safe builder (redirect(none) + connect-time
                                                                                       // ControllerSsrfResolver) — same user-supplied SLA-webhook + DNS-rebinding
                                                                                       // rationale as the sibling SLA-monitor client above (PR #162).
        let client =
            talos_http_utils::outbound::build_outbound_webhook_client("talos-sla-webhook/1.0")
                .expect("SLA monitor: failed to build hardened reqwest client");
        loop {
            let should_proceed = tokio::select! {
                _ = interval.tick() => true,
                _ = shutdown.changed() => !*shutdown.borrow(),
            };
            if !should_proceed {
                tracing::info!("SLA threshold breach loop received shutdown signal");
                break;
            }

            // Load all thresholds with their workflow's user_id for scoped queries
            let thresholds = sqlx::query(
                "SELECT t.workflow_id, t.user_id, t.p95_latency_ms, \
                        t.success_rate_pct::float8 AS success_rate_pct, \
                        t.notification_webhook \
                 FROM workflow_sla_thresholds t",
            )
            .fetch_all(&sla_pool)
            .await;

            let thresholds = match thresholds {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!("SLA threshold check: failed to load thresholds: {}", e);
                    continue;
                }
            };

            for row in &thresholds {
                use sqlx::Row;
                let workflow_id: uuid::Uuid = row.get("workflow_id");
                let user_id: uuid::Uuid = row.get("user_id");
                let p95_threshold: Option<i64> = row.get("p95_latency_ms");
                let success_threshold: Option<f64> = row.get("success_rate_pct");
                let webhook: String = row.get("notification_webhook");

                // Re-validate at fire time. Stored URLs that predate the
                // r285 SSRF hardening (obfuscated IPv4 — octal/hex/integer
                // encodings) were accepted at write time but resolve to
                // internal IPs at fire time. Skip rather than fire.
                if let Err(reason) = crate::mcp::utils::check_outbound_url_no_ssrf(&webhook) {
                    tracing::warn!(
                        workflow_id = %workflow_id,
                        "SLA monitor: skipping fire — stored webhook fails SSRF re-check: {reason}"
                    );
                    continue;
                }

                // Query last-24h stats
                let stats = sqlx::query(
                    "SELECT \
                        COUNT(*) FILTER (WHERE status = 'completed')::bigint AS succeeded, \
                        COUNT(*)::bigint AS total, \
                        PERCENTILE_CONT(0.95) WITHIN GROUP \
                            (ORDER BY EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000) \
                            AS p95_ms \
                     FROM workflow_executions \
                     WHERE workflow_id = $1 AND user_id = $2 \
                       AND started_at > NOW() - INTERVAL '24 hours' \
                       AND completed_at IS NOT NULL",
                )
                .bind(workflow_id)
                .bind(user_id)
                .fetch_one(&sla_pool)
                .await;

                let stats = match stats {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                let total: i64 = stats.get("total");
                if total == 0 {
                    continue;
                }
                let succeeded: i64 = stats.get("succeeded");
                let p95_ms: Option<f64> = stats.get("p95_ms");
                let actual_success_pct = (succeeded as f64 / total as f64) * 100.0;

                let now = chrono::Utc::now().to_rfc3339();

                // Check p95 latency breach
                if let (Some(threshold), Some(actual)) = (p95_threshold, p95_ms) {
                    if actual > threshold as f64 {
                        let payload = serde_json::json!({
                            "event": "sla_breach",
                            "workflow_id": workflow_id,
                            "metric": "p95_latency_ms",
                            "threshold": threshold,
                            "actual": actual as i64,
                            "timestamp": now,
                        });
                        tracing::warn!(
                            workflow_id = %workflow_id,
                            threshold = threshold,
                            actual = actual as i64,
                            "SLA breach: p95 latency exceeded"
                        );
                        let client = client.clone();
                        let webhook = webhook.clone();
                        // MCP-809 (2026-05-14): canonical 3-arm match.
                        // Pre-fix this fire only logged on Err — an
                        // operator-supplied webhook returning 4xx/5xx
                        // (e.g. PagerDuty rate-limited / Slack 503 /
                        // OpsGenie 502) was silently treated as
                        // success. The sibling 15-min SLA-degradation
                        // fire at ~line 2209 already follows the canonical
                        // shape (MCP-774); this 5-min SLA-breach task
                        // had drifted. Same misleading-success class as
                        // MCP-737/738/800/801. WARN+target talos_rpc so
                        // dashboards correlate delivery-failure rate
                        // with controller health.
                        tokio::spawn(async move {
                            match client.post(&webhook).json(&payload).send().await {
                                Ok(resp) if resp.status().is_success() => {
                                    tracing::debug!(
                                        webhook = %webhook,
                                        status = resp.status().as_u16(),
                                        "SLA-breach (p95) webhook delivered"
                                    );
                                }
                                Ok(resp) => {
                                    tracing::warn!(
                                        target: "talos_rpc",
                                        webhook = %webhook,
                                        status = resp.status().as_u16(),
                                        "SLA-breach (p95) webhook returned non-success status — operator notification may not have reached its destination"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        target: "talos_rpc",
                                        webhook = %webhook,
                                        error = %e,
                                        "SLA-breach (p95) webhook POST failed — operator notification undelivered"
                                    );
                                }
                            }
                        });
                    }
                }

                // Check success rate breach
                if let Some(threshold) = success_threshold {
                    if actual_success_pct < threshold {
                        let payload = serde_json::json!({
                            "event": "sla_breach",
                            "workflow_id": workflow_id,
                            "metric": "success_rate_pct",
                            "threshold": threshold,
                            "actual": (actual_success_pct * 100.0).round() / 100.0,
                            "timestamp": now,
                        });
                        tracing::warn!(
                            workflow_id = %workflow_id,
                            threshold = threshold,
                            actual = actual_success_pct,
                            "SLA breach: success rate below threshold"
                        );
                        let client = client.clone();
                        let webhook = webhook.clone();
                        // MCP-809 (2026-05-14): same misleading-success drift
                        // as the p95 sibling above; mirror the canonical
                        // 3-arm match. See p95 comment for rationale.
                        tokio::spawn(async move {
                            match client.post(&webhook).json(&payload).send().await {
                                Ok(resp) if resp.status().is_success() => {
                                    tracing::debug!(
                                        webhook = %webhook,
                                        status = resp.status().as_u16(),
                                        "SLA-breach (success-rate) webhook delivered"
                                    );
                                }
                                Ok(resp) => {
                                    tracing::warn!(
                                        target: "talos_rpc",
                                        webhook = %webhook,
                                        status = resp.status().as_u16(),
                                        "SLA-breach (success-rate) webhook returned non-success status — operator notification may not have reached its destination"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        target: "talos_rpc",
                                        webhook = %webhook,
                                        error = %e,
                                        "SLA-breach (success-rate) webhook POST failed — operator notification undelivered"
                                    );
                                }
                            }
                        });
                    }
                }
            }
        }
    });
    tracing::info!("SLA threshold breach check task started (runs every 5 minutes)");
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
use rpc_subscribers::{
    spawn_database_rpc_subscriber, spawn_graph_rpc_subscriber, spawn_integration_state_subscriber,
    spawn_integration_state_sweeper, spawn_memory_rpc_subscriber, spawn_ml_rpc_subscriber,
    spawn_state_write_subscriber,
};

/// RFC 0010 P2 inc.4: load the active `worker_identities` registry and install it
/// as job_protocol's dynamic verifying-key overlay (union with the env base).
/// Returns the number of keys installed. A stored key that is not a canonical
/// Ed25519 point is skipped with a warning rather than poisoning the snapshot —
/// one bad row can't strand the fleet (same fail-open-per-entry posture as the
/// env-registry parser). Shared by the boot load, the periodic refresh task, and
/// (inc.4c) the eager refresh after a registration write.
async fn refresh_worker_key_overlay(
    repo: &talos_worker_identity_repository::WorkerIdentityRepository,
) -> anyhow::Result<usize> {
    let entries = repo.load_active_registry().await?;
    let mut mapped = Vec::with_capacity(entries.len());
    for entry in entries {
        match talos_workflow_job_protocol::parse_ed25519_verifying_key_bytes(&entry.public_key) {
            Ok(vk) => mapped.push((entry.worker_id, vk)),
            Err(err) => tracing::warn!(
                target: "talos_engine",
                worker_id = %entry.worker_id,
                error = %err,
                "skipping malformed worker_identities public key"
            ),
        }
    }
    let installed = mapped.len();
    talos_workflow_job_protocol::set_dynamic_worker_public_keys(mapped);
    Ok(installed)
}

// ===== RFC 0010 P2 inc.4c: in-cluster worker self-registration endpoint =====
//
// `POST /internal/worker-key` — an autoscaling worker registers its Ed25519
// public key at boot without an operator touching a ConfigMap. Because workers
// run untrusted WASM and are credential-free, this endpoint is defended in depth:
//   1. NetworkPolicy (chart) restricts ingress to worker pods, in-cluster only —
//      the route is never exposed via nginx/Traefik (`no-nginx-route`).
//   2. A constant-time shared bearer token (TALOS_WORKER_REGISTRATION_TOKEN)
//      gates callers; when it is unset the route is not even mounted.
//   3. An Ed25519 proof-of-possession over the request proves the caller holds
//      the private key for the key it is registering (job_protocol PoP helpers).
//   4. A freshness window bounds replay of a captured request; registration is
//      idempotent so replay is otherwise benign.
//   5. The inc.4a per-worker active-key cap bounds table inflation.
//   6. TRUST-ON-FIRST-USE (P2 hardening): the shared token proves "a legit
//      worker pod", not a specific worker_id, so this path binds each worker_id
//      to its FIRST registered key. After that, only an idempotent refresh of
//      that exact active key is accepted — a different key, a revoked key, or a
//      claim on a retired worker_id is a 409 (`register_tofu`). Without this, a
//      compromised token-holder could register its own key under another
//      worker's id and impersonate it for result signing / P3 secret claims.
//      Rotation and revocation reversal are operator actions (the
//      `register-worker-identity` CLI, DB-credentialed) — workers never
//      generate keys in-pod, so a legitimate new key always accompanies an
//      operator anyway.
//
//   7. PER-WORKER PROVISIONING TOKENS (P2 hardening inc.2): a bearer that is
//      not the shared token is treated as a single-use provisioning token —
//      operator-minted, expiring, stored as SHA-256 only, and (when bound to a
//      worker_id) redeemable only for that worker. Consumption is atomic inside
//      the registration transaction; a refused registration does not burn the
//      token. `TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN=1` is the migration
//      end-state: shared token and wildcard tokens are refused, so EVERY
//      registration is an explicit operator grant for one worker_id — closing
//      the first-come-first-served residual TOFU leaves on never-before-seen
//      worker_ids.
//
// Residual (documented in the RFC): while enforcement is OFF (migration
// window), a shared-token/wildcard holder can still claim a never-before-seen
// worker_id first. mTLS client-certs with a worker_id-bound SAN remain the
// long-term alternative.

/// Registration-auth config, injected as an axum `Extension` on the internal
/// sub-router. At least one scheme is configured whenever the route is mounted.
/// No `Debug` derive — `shared_token` is a live bearer credential (check 37).
#[derive(Clone)]
struct WorkerRegAuth {
    /// Legacy shared bearer (`TALOS_WORKER_REGISTRATION_TOKEN`). `None` in a
    /// bound-token-only deployment.
    shared_token: Option<std::sync::Arc<String>>,
    /// `TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN=1` — the migration end-state:
    /// only single-use provisioning tokens BOUND to a worker_id register;
    /// the shared token and wildcard tokens are refused. Mirrors the
    /// accept-legacy-then-require rollout P1/P2 used for signing schemes.
    require_bound: bool,
}

/// Which authentication path a presented bearer takes. Decided by constant-time
/// comparison against the shared token; everything that is NOT the shared
/// token is treated as a provisioning-token candidate and resolved against the
/// DB (hashed lookup), so the classifier itself leaks nothing about validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegBearerPath {
    /// Matches the shared token and enforcement is off → TOFU registration.
    LegacyShared,
    /// Matches the shared token but bound-token enforcement is on → refuse
    /// (distinct variant only so the handler can log the policy hit; the
    /// client response stays generic).
    SharedRefusedByPolicy,
    /// Anything else → try single-use provisioning-token redemption.
    Provisioning,
}

/// Classify the presented (non-empty) bearer.
fn classify_registration_bearer(
    provided: &str,
    shared: Option<&str>,
    require_bound: bool,
) -> RegBearerPath {
    use subtle::ConstantTimeEq;
    let is_shared = shared.is_some_and(|s| {
        // Length check first (ct_eq requires equal length); the compare itself
        // is constant-time so the token can't be recovered by timing.
        provided.len() == s.len() && bool::from(provided.as_bytes().ct_eq(s.as_bytes()))
    });
    match (is_shared, require_bound) {
        (true, false) => RegBearerPath::LegacyShared,
        (true, true) => RegBearerPath::SharedRefusedByPolicy,
        (false, _) => RegBearerPath::Provisioning,
    }
}

#[derive(serde::Deserialize)]
struct WorkerKeyRegistrationRequest {
    worker_id: String,
    /// Hex Ed25519 verifying key (32 bytes) being registered.
    public_key: String,
    #[serde(default)]
    supports_sealing: bool,
    /// Unix-millis when the worker built the request (freshness).
    issued_at_ms: u64,
    /// Anti-grinding nonce, bound into the proof.
    nonce: String,
    /// Hex Ed25519 signature (64 bytes) over the canonical PoP message.
    proof: String,
}

/// Freshness tolerances for a registration request. Asymmetric like `rpc_auth`:
/// generous on the past (clock skew + in-flight latency), tight on the future.
const WORKER_REG_PAST_MS: u64 = 300_000;
const WORKER_REG_FUTURE_MS: u64 = 60_000;

/// Freshness window for a registration request: reject stale (past the window)
/// or future-dated requests. Pure so it is unit-testable without a live server.
/// The client-facing message leaks no internal state.
fn check_registration_freshness(
    issued_at_ms: u64,
    now_ms: u64,
) -> Result<(), (axum::http::StatusCode, &'static str)> {
    use axum::http::StatusCode;
    if issued_at_ms.saturating_add(WORKER_REG_PAST_MS) < now_ms {
        return Err((StatusCode::BAD_REQUEST, "registration request expired"));
    }
    if issued_at_ms > now_ms.saturating_add(WORKER_REG_FUTURE_MS) {
        return Err((
            StatusCode::BAD_REQUEST,
            "registration issued_at is in the future",
        ));
    }
    Ok(())
}

/// SHA-256 hex of a presented bearer — the shape stored in
/// `worker_provisioning_tokens.token_hash`. The raw token is neither stored
/// nor used in any SQL comparison (lint check 41 discipline).
fn provisioning_token_hash(raw: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(raw.as_bytes()))
}

/// Extract a `Bearer <token>` value from the Authorization header.
fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn worker_reg_error(
    status: axum::http::StatusCode,
    message: &str,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    (status, axum::Json(serde_json::json!({ "error": message })))
}

async fn register_worker_key_handler(
    Extension(db_pool): Extension<sqlx::PgPool>,
    Extension(auth): Extension<WorkerRegAuth>,
    headers: axum::http::HeaderMap,
    axum::Json(req): axum::Json<WorkerKeyRegistrationRequest>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    use axum::http::StatusCode;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // 1) Bearer presence + freshness. Which auth path the bearer takes is
    //    decided AFTER shape + proof-of-possession pass, so a garbage request
    //    can never consume a single-use provisioning token.
    let Some(provided_bearer) = bearer_token(&headers) else {
        return worker_reg_error(StatusCode::UNAUTHORIZED, "missing bearer token");
    };
    if let Err((status, msg)) = check_registration_freshness(req.issued_at_ms, now_ms) {
        return worker_reg_error(status, msg);
    }

    // 2) Shape validation — worker_id charset + 32-byte canonical Ed25519 point.
    if let Err(e) = talos_workflow_job_protocol::validate_worker_id(&req.worker_id) {
        return worker_reg_error(StatusCode::BAD_REQUEST, leak_safe_validation(&e));
    }
    let public_key = match hex::decode(req.public_key.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
    {
        Some(pk) => pk,
        None => {
            return worker_reg_error(
                StatusCode::BAD_REQUEST,
                "public_key must be 64-char hex (32-byte Ed25519 key)",
            )
        }
    };
    let proof = match hex::decode(req.proof.trim()) {
        Ok(p) => p,
        Err(_) => return worker_reg_error(StatusCode::BAD_REQUEST, "proof must be hex"),
    };

    // 3) Proof-of-possession: the request is signed by the private key for the
    //    key being registered, binding every field.
    if talos_workflow_job_protocol::verify_worker_registration_proof(
        &public_key,
        &req.worker_id,
        req.supports_sealing,
        req.issued_at_ms,
        &req.nonce,
        &proof,
    )
    .is_err()
    {
        // Deliberately generic — do not distinguish "bad key" from "bad sig".
        return worker_reg_error(StatusCode::UNAUTHORIZED, "proof-of-possession failed");
    }

    // 4) Auth-path decision + persistence, then (on success) an eager refresh
    //    of the verify overlay so the worker's very first result verifies
    //    immediately. Shared token → TOFU rule (first key wins; only that key
    //    may refresh itself here). Anything else → single-use provisioning
    //    token: bound tokens carry operator-grade rotation semantics, wildcard
    //    tokens carry TOFU semantics and are refused entirely under
    //    TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN=1.
    let repo = talos_worker_identity_repository::WorkerIdentityRepository::new(db_pool);
    let path = classify_registration_bearer(
        provided_bearer,
        auth.shared_token.as_deref().map(String::as_str),
        auth.require_bound,
    );
    let outcome = match path {
        RegBearerPath::SharedRefusedByPolicy => {
            tracing::warn!(
                target: "talos_security",
                event_kind = "worker_reg_shared_token_refused",
                worker_id = %req.worker_id,
                "shared registration token presented but bound-token enforcement \
                 (TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN) is on; refusing. Mint a \
                 worker_id-bound provisioning token for this worker instead."
            );
            return worker_reg_error(StatusCode::UNAUTHORIZED, "invalid registration token");
        }
        RegBearerPath::LegacyShared => repo
            .register_tofu(&req.worker_id, &public_key, req.supports_sealing)
            .await
            .map(|o| match o {
                talos_worker_identity_repository::TofuOutcome::Registered => {
                    talos_worker_identity_repository::TokenRegisterOutcome::Registered
                }
                talos_worker_identity_repository::TofuOutcome::IdentityConflict => {
                    talos_worker_identity_repository::TokenRegisterOutcome::IdentityConflict
                }
            }),
        RegBearerPath::Provisioning => {
            // Hash the presented bearer; only the digest touches SQL. An
            // unknown/used/expired/revoked/misbound token collapses into ONE
            // client-facing 401 below.
            let token_hash = provisioning_token_hash(provided_bearer);
            repo.register_with_provisioning_token(
                &token_hash,
                &req.worker_id,
                &public_key,
                req.supports_sealing,
                auth.require_bound,
            )
            .await
        }
    };

    match outcome {
        Ok(talos_worker_identity_repository::TokenRegisterOutcome::Registered) => {
            if let Err(e) = refresh_worker_key_overlay(&repo).await {
                // Non-fatal: the periodic task will pick it up within its interval.
                tracing::warn!(
                    target: "talos_engine",
                    error = %e,
                    "eager worker-key overlay refresh after registration failed"
                );
            }
            tracing::info!(
                target: "talos_engine",
                event_kind = "worker_key_registered",
                worker_id = %req.worker_id,
                supports_sealing = req.supports_sealing,
                auth_path = ?path,
                "worker self-registered an Ed25519 identity key"
            );
            (
                StatusCode::OK,
                axum::Json(serde_json::json!({ "status": "registered" })),
            )
        }
        Ok(talos_worker_identity_repository::TokenRegisterOutcome::InvalidToken) => {
            // Server-side detail, generic client response: presence only, never
            // the token value.
            tracing::warn!(
                target: "talos_security",
                event_kind = "worker_reg_token_invalid",
                worker_id = %req.worker_id,
                "worker-key registration refused: no eligible provisioning token \
                 (unknown, used, expired, revoked, bound to another worker_id, or \
                 wildcard under bound-token enforcement)"
            );
            worker_reg_error(StatusCode::UNAUTHORIZED, "invalid registration token")
        }
        Ok(talos_worker_identity_repository::TokenRegisterOutcome::IdentityConflict) => {
            // The single loudest signal this endpoint can emit: a token-holder
            // tried to bind a key that is NOT this worker_id's trusted key —
            // either in-fleet impersonation or an unmanaged rotation. Public
            // key material only (never the bearer token).
            tracing::warn!(
                target: "talos_security",
                event_kind = "worker_key_tofu_conflict",
                worker_id = %req.worker_id,
                submitted_public_key = %hex::encode(public_key),
                auth_path = ?path,
                "worker-key registration REFUSED: worker_id already has a bound \
                 identity and the submitted key does not match its active key. \
                 Possible in-fleet impersonation attempt; legitimate rotation \
                 goes through the register-worker-identity operator CLI or a \
                 worker_id-bound provisioning token."
            );
            worker_reg_error(
                StatusCode::CONFLICT,
                "worker_id already has a registered identity; rotation requires operator action",
            )
        }
        Ok(talos_worker_identity_repository::TokenRegisterOutcome::CapReached) => worker_reg_error(
            StatusCode::TOO_MANY_REQUESTS,
            "worker already holds the maximum active keys; deactivate one first",
        ),
        Err(e) => {
            // Log full error server-side; return a generic message (no schema leak).
            tracing::error!(
                target: "talos_engine",
                worker_id = %req.worker_id,
                error = %e,
                "worker-key registration DB write failed"
            );
            worker_reg_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "registration failed (see server logs)",
            )
        }
    }
}

/// Collapse the job_protocol validation error to one of a small set of fixed,
/// leak-safe messages (the raw error only ever describes the charset rule, but
/// this keeps the response surface stable and audited).
fn leak_safe_validation(_e: &str) -> &'static str {
    "invalid worker_id (allowed: A-Z a-z 0-9 . - _, non-empty, bounded length)"
}

// ---------- worker-identity registry subcommands (RFC 0010 P2 inc.4) --------
//
// Operator-facing management of the `worker_identities` DB registry. Workers are
// credential-free (no Postgres), so THEY self-register over the HTTP endpoint;
// these subcommands are the OPERATOR path — pre-registering keys, auditing the
// registry, and retiring rotated-out keys — run from a context that already
// holds DB credentials (the controller image as a one-shot Job). Direct DB
// access is its own authorization, so no proof-of-possession is required here
// (that gate exists on the network self-registration endpoint).
async fn run_worker_identity_cli(sub: &str, args: &[String]) -> anyhow::Result<()> {
    use talos_worker_identity_repository::{RegisterOutcome, WorkerIdentityRepository};

    let mut worker_id: Option<String> = None;
    let mut public_key_hex: Option<String> = None;
    let mut supports_sealing = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--worker-id" => {
                worker_id = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--worker-id requires a value"))?
                        .clone(),
                );
            }
            "--public-key" => {
                public_key_hex = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--public-key requires a value"))?
                        .clone(),
                );
            }
            "--supports-sealing" => supports_sealing = true,
            other => anyhow::bail!("unknown {sub} flag: {other}"),
        }
    }

    let pool = crate::db::init_pool().await?;
    let repo = WorkerIdentityRepository::new(pool);

    // Shared parse+validate for the two subcommands that take a key.
    let resolve_key =
        |worker_id: &Option<String>, hex: &Option<String>| -> anyhow::Result<(String, [u8; 32])> {
            let wid = worker_id
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--worker-id is required"))?;
            talos_workflow_job_protocol::validate_worker_id(&wid)
                .map_err(|e| anyhow::anyhow!("invalid --worker-id: {e}"))?;
            let hex = hex.clone().ok_or_else(|| {
                anyhow::anyhow!("--public-key is required (64-char hex Ed25519 key)")
            })?;
            // Parse through the canonical loader so a non-point is rejected here, not
            // at verify time — the stored key is guaranteed a valid Ed25519 point.
            let vk = talos_workflow_job_protocol::parse_ed25519_verifying_key_hex(&hex)
                .map_err(|e| anyhow::anyhow!("invalid --public-key: {e}"))?;
            Ok((wid, vk.to_bytes()))
        };

    match sub {
        "register-worker-identity" => {
            let (wid, pk) = resolve_key(&worker_id, &public_key_hex)?;
            match repo.register(&wid, &pk, supports_sealing).await? {
                RegisterOutcome::Registered => {
                    println!("registered worker '{wid}' (supports_sealing={supports_sealing})");
                }
                RegisterOutcome::CapReached => anyhow::bail!(
                    "worker '{wid}' already holds the maximum active keys \
                     ({}); deactivate one before adding another",
                    talos_worker_identity_repository::MAX_ACTIVE_KEYS_PER_WORKER
                ),
            }
        }
        "deactivate-worker-identity" => {
            let (wid, pk) = resolve_key(&worker_id, &public_key_hex)?;
            if repo.deactivate(&wid, &pk).await? {
                println!("deactivated one key for worker '{wid}'");
            } else {
                println!("no active key matched for worker '{wid}' (already retired or absent)");
            }
        }
        "list-worker-identities" => {
            let rows = repo.list().await?;
            if rows.is_empty() {
                println!("(worker-identity registry is empty)");
            }
            for r in rows {
                println!(
                    "{wid}\t{key}\tsealing={sealing}\tactive={active}\tlast_seen={seen}",
                    wid = r.worker_id,
                    key = hex::encode(r.public_key),
                    sealing = r.supports_sealing,
                    active = r.active,
                    seen = r.last_seen_at.to_rfc3339(),
                );
            }
        }
        _ => unreachable!("dispatch guarded by the match in main()"),
    }
    Ok(())
}

// ------- worker provisioning-token subcommands (RFC 0010 P2 inc.2/3) --------
//
// Operator mint/list/revoke for `worker_provisioning_tokens` — the single-use,
// worker_id-bound credentials the registration endpoint redeems. Same trust
// model as the worker-identity subcommands above: DB credentials ARE the
// authorization. The raw token is printed ONCE to stdout (like
// generate-worker-trust-keypair) and only its SHA-256 is stored; mints and
// revokes append to `admin_event_log` (user_id NULL — no platform user exists
// on this path) so the token lifecycle is auditable end-to-end.
async fn run_worker_provisioning_token_cli(sub: &str, args: &[String]) -> anyhow::Result<()> {
    use talos_worker_identity_repository::WorkerIdentityRepository;

    let mut worker_id: Option<String> = None;
    let mut wildcard = false;
    let mut ttl_hours: i64 = 24;
    let mut note: Option<String> = None;
    let mut id: Option<uuid::Uuid> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--worker-id" => {
                worker_id = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--worker-id requires a value"))?
                        .clone(),
                );
            }
            "--wildcard" => wildcard = true,
            "--ttl-hours" => {
                ttl_hours = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--ttl-hours requires a value"))?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("--ttl-hours must be an integer"))?;
            }
            "--note" => {
                note = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--note requires a value"))?
                        .clone(),
                );
            }
            "--id" => {
                id = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--id requires a value"))?
                        .parse()
                        .map_err(|_| anyhow::anyhow!("--id must be a UUID"))?,
                );
            }
            other => anyhow::bail!("unknown {sub} flag: {other}"),
        }
    }

    let pool = crate::db::init_pool().await?;
    let repo = WorkerIdentityRepository::new(pool);

    match sub {
        "mint-worker-provisioning-token" => {
            // Binding is an explicit choice: wildcard must be SPELLED OUT, so
            // an operator can't mint an any-worker token by forgetting a flag.
            let binding = match (&worker_id, wildcard) {
                (Some(_), true) => {
                    anyhow::bail!("--worker-id and --wildcard are mutually exclusive")
                }
                (None, false) => anyhow::bail!(
                    "specify --worker-id <id> (bound, recommended) or --wildcard (migration \
                     compat; refused when TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN=1)"
                ),
                (Some(wid), false) => {
                    talos_workflow_job_protocol::validate_worker_id(wid)
                        .map_err(|e| anyhow::anyhow!("invalid --worker-id: {e}"))?;
                    Some(wid.clone())
                }
                (None, true) => None,
            };
            if !(1..=24 * 30).contains(&ttl_hours) {
                anyhow::bail!("--ttl-hours must be between 1 and 720 (30 days)");
            }
            // Bound the note so the audit/list surfaces stay sane.
            if note.as_ref().is_some_and(|n| n.len() > 500) {
                anyhow::bail!("--note must be at most 500 bytes");
            }

            // 32 bytes of OS entropy, hex-encoded, prefixed for greppability.
            // Only the SHA-256 of this string is persisted.
            let raw_token = {
                use rand::RngCore;
                let mut buf = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut buf);
                format!("wpt_{}", hex::encode(buf))
            };
            let expires_at = chrono::Utc::now() + chrono::Duration::hours(ttl_hours);
            let token_id = repo
                .create_provisioning_token(
                    &provisioning_token_hash(&raw_token),
                    binding.as_deref(),
                    expires_at,
                    note.as_deref(),
                )
                .await?;
            repo.insert_provisioning_token_audit(
                "worker_provisioning_token_minted",
                token_id,
                &format!(
                    "minted worker provisioning token for {} (ttl {ttl_hours}h)",
                    binding.as_deref().unwrap_or("WILDCARD")
                ),
                Some(&serde_json::json!({
                    "worker_id": binding,
                    "expires_at": expires_at.to_rfc3339(),
                    "note": note,
                })),
            )
            .await?;

            eprintln!("# ─────────────────────────────────────────────────────────────────────");
            eprintln!("# Worker provisioning token — shown ONCE, only its SHA-256 is stored.");
            eprintln!("# Hand it to exactly ONE worker pod as its registration bearer, then");
            eprintln!("# discard it. Single-use; expires {expires_at}.");
            eprintln!("# ─────────────────────────────────────────────────────────────────────");
            match &binding {
                Some(wid) => println!("# ── on WORKER '{wid}' (bound: registers only this id) ──"),
                None => println!("# ── WILDCARD token (any worker_id, TOFU rule applies) ──"),
            }
            println!("TALOS_WORKER_REGISTRATION_TOKEN={raw_token}");
            println!("# token id: {token_id}  (revoke-worker-provisioning-token --id {token_id})");
        }
        "list-worker-provisioning-tokens" => {
            let rows = repo.list_provisioning_tokens().await?;
            if rows.is_empty() {
                println!("(no worker provisioning tokens minted)");
            }
            let now = chrono::Utc::now();
            for r in rows {
                // One derived status keeps the listing scannable; precedence
                // mirrors the redeem SQL (used beats revoked beats expired).
                let status = if let Some(used) = r.used_at {
                    format!(
                        "USED by '{}' at {}",
                        r.used_by_worker_id.as_deref().unwrap_or("?"),
                        used.to_rfc3339()
                    )
                } else if let Some(revoked) = r.revoked_at {
                    format!("REVOKED at {}", revoked.to_rfc3339())
                } else if r.expires_at <= now {
                    "EXPIRED".to_string()
                } else {
                    "live".to_string()
                };
                println!(
                    "{id}\t{binding}\texpires={expires}\t{status}\t{note}",
                    id = r.id,
                    binding = r
                        .worker_id
                        .as_deref()
                        .map(|w| format!("worker={w}"))
                        .unwrap_or_else(|| "WILDCARD".to_string()),
                    expires = r.expires_at.to_rfc3339(),
                    note = r.note.as_deref().unwrap_or(""),
                );
            }
        }
        "revoke-worker-provisioning-token" => {
            let id = id.ok_or_else(|| anyhow::anyhow!("--id <uuid> is required"))?;
            if repo.revoke_provisioning_token(id).await? {
                repo.insert_provisioning_token_audit(
                    "worker_provisioning_token_revoked",
                    id,
                    "revoked worker provisioning token",
                    None,
                )
                .await?;
                println!("revoked provisioning token {id}");
            } else {
                println!(
                    "token {id} was not live (already used, already revoked, or unknown) — \
                     nothing changed"
                );
            }
        }
        _ => unreachable!("dispatch guarded by the match in main()"),
    }
    Ok(())
}

// ---------- `controller generate-worker-trust-keypair` subcommand ----------
//
// RFC 0010 (asymmetric worker-trust boundary). Mints an Ed25519 keypair in the
// exact hex shape the env loaders accept and prints a copy-pasteable env block
// telling the operator which half goes on which process. This is the ONE
// supported way to generate keys for the boundary — hand-rolling with openssl
// produces the wrong encoding (the loaders want a raw 32-byte seed / point in
// hex, not a PKCS#8/PEM wrapper).
//
// Two roles, because the boundary has two independent keypairs:
//   --role controller            controller SIGNS dispatches, workers VERIFY.
//                                seed → TALOS_CONTROLLER_SIGNING_KEY (controller)
//                                pub  → TALOS_CONTROLLER_PUBLIC_KEY  (workers)
//   --role worker --worker-id ID this worker SIGNS results + RPC, controller VERIFIES.
//                                seed → TALOS_WORKER_SIGNING_KEY (this worker)
//                                pub  → TALOS_WORKER_PUBLIC_KEYS entry (controller)
//
// The seed is a PRIVATE key: it prints to stdout (the standard keygen pattern,
// like `wg genkey`) so the operator can capture it into a Secret, and a loud
// stderr banner reminds them never to commit it. Nothing is logged via
// `tracing` — the value never touches the structured log surface.
fn run_generate_worker_trust_keypair_cli(args: &[String]) -> anyhow::Result<()> {
    let mut role: Option<String> = None;
    let mut worker_id: Option<String> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--role" => {
                role = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--role requires a value"))?
                        .clone(),
                );
            }
            "--worker-id" => {
                worker_id = Some(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--worker-id requires a value"))?
                        .clone(),
                );
            }
            other => anyhow::bail!("unknown generate-worker-trust-keypair flag: {other}"),
        }
    }
    let role = role.ok_or_else(|| anyhow::anyhow!("--role is required (controller|worker)"))?;

    let (seed_hex, pub_hex) = talos_workflow_job_protocol::generate_ed25519_keypair_hex();

    // Secret-handling banner on stderr so it's visible even when stdout is
    // piped into a file/secret.
    eprintln!("# ─────────────────────────────────────────────────────────────────────");
    eprintln!("# RFC 0010 worker-trust keypair ({role}). The SIGNING key below is");
    eprintln!("# SECRET — store it in a Kubernetes Secret / KMS, hand it to exactly");
    eprintln!("# one process, and NEVER commit it. The PUBLIC key is safe to share.");
    eprintln!("# ─────────────────────────────────────────────────────────────────────");

    match role.as_str() {
        "controller" => {
            println!("# ── on the CONTROLLER (signs dispatches) ──");
            println!("TALOS_DISPATCH_SCHEME=ed25519");
            println!("TALOS_CONTROLLER_SIGNING_KEY={seed_hex}");
            println!();
            println!("# ── on EVERY WORKER (verifies dispatches) ──");
            println!("TALOS_CONTROLLER_PUBLIC_KEY={pub_hex}");
            println!("# During a controller-key rotation, keep the previous public key for an");
            println!("# overlap window: TALOS_CONTROLLER_PUBLIC_KEY_PREVIOUS=<old_pub>[,<older>]");
        }
        "worker" => {
            let wid = worker_id
                .ok_or_else(|| anyhow::anyhow!("--worker-id is required for --role worker"))?;
            // The id is bound into every Ed25519 result/RPC signature and used
            // as the controller's lookup key, so it must satisfy the same
            // validator the worker applies at sign time.
            talos_workflow_job_protocol::validate_worker_id(&wid)
                .map_err(|e| anyhow::anyhow!("invalid --worker-id: {e}"))?;
            println!("# ── on WORKER '{wid}' (signs job results + RPC) ──");
            println!("TALOS_WORKER_SIGNING_KEY={seed_hex}");
            println!();
            println!("# ── on the CONTROLLER (verifies this worker) ──");
            println!("# Append to TALOS_WORKER_PUBLIC_KEYS (comma-separated worker_id=hex pairs;");
            println!("# repeat the same id with a new key for a rotation overlap window):");
            println!("TALOS_WORKER_PUBLIC_KEYS={wid}={pub_hex}");
        }
        other => anyhow::bail!("unknown --role '{other}' (expected controller|worker)"),
    }
    Ok(())
}

// ---------- `controller publish-templates` subcommand ----------
//
// Compiles every template in `--templates-dir` (default: `module-templates/`)
// using the same `CompilationService` the running controller uses, and emits
// a registry-ready bundle to `--output`:
//
//   {output}/
//     {template-name}/
//       talos.json   — manifest copied verbatim
//       module.wasm  — cargo-component build output
//     _index.json    — discovery index, format matches sync.rs::IndexConfig
//
// CI then iterates each subdirectory and runs `oras push` to publish the
// artifacts to the configured registry. See
// `.github/workflows/template-publish.yml`.
//
// This subcommand exists so CI doesn't have to replicate the cargo-component
// scaffolding (Cargo.toml + lib.rs wrapper + WIT bindings) in YAML — that
// scaffold lives in `compilation::CompilationService` and would drift the
// moment one was edited without the other. By shelling out to the controller
// binary itself, CI always uses the same compilation pipeline as production.
async fn run_publish_templates_cli(args: &[String]) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use std::path::PathBuf;

    // Tiny flag parser — clap is overkill for two options and would pull in
    // the dependency just for this subcommand.
    let mut templates_dir = PathBuf::from("module-templates");
    let mut output_dir: Option<PathBuf> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--templates-dir" => {
                templates_dir = PathBuf::from(
                    iter.next()
                        .ok_or_else(|| anyhow::anyhow!("--templates-dir requires a value"))?,
                );
            }
            "--output" => {
                output_dir =
                    Some(PathBuf::from(iter.next().ok_or_else(|| {
                        anyhow::anyhow!("--output requires a value")
                    })?));
            }
            other => anyhow::bail!("unknown publish-templates flag: {other}"),
        }
    }
    let output_dir = output_dir.ok_or_else(|| {
        anyhow::anyhow!("--output is required (path where artifacts will be written)")
    })?;

    if !templates_dir.exists() {
        anyhow::bail!(
            "templates dir not found: {} (set --templates-dir or run from the workspace root)",
            templates_dir.display()
        );
    }
    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("create --output dir {}", output_dir.display()))?;

    // Stand up a minimal CompilationService — same constructor the server
    // uses, plus a no-op event channel so progress events are dropped.
    let workspace_root = std::env::temp_dir().join("talos-publish-workspace");
    let (event_tx, _rx) = tokio::sync::broadcast::channel::<engine::events::CompilationEvent>(64);
    let svc = CompilationService::new(workspace_root, event_tx);

    let mut index_entries: Vec<serde_json::Value> = Vec::new();
    let mut compiled = 0usize;
    let mut skipped = 0usize;

    let entries = std::fs::read_dir(&templates_dir)
        .with_context(|| format!("read --templates-dir {}", templates_dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest_path = path.join("talos.json");
        let template_path = path.join("template.rs");
        if !manifest_path.exists() || !template_path.exists() {
            skipped += 1;
            continue;
        }

        let manifest_str = std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("read {}", manifest_path.display()))?;
        let manifest_json: serde_json::Value = serde_json::from_str(&manifest_str)
            .with_context(|| format!("parse {}", manifest_path.display()))?;

        // `name` is the OCI repo name (kebab-case, lowercase, no spaces);
        // `version` becomes the OCI tag. Both are required for publishing.
        let name = manifest_json
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("{} missing required `name`", manifest_path.display()))?
            .to_string();
        let tag = manifest_json
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("latest")
            .to_string();

        let source = std::fs::read_to_string(&template_path)
            .with_context(|| format!("read {}", template_path.display()))?;

        eprintln!("publish-templates: compiling {name} v{tag}");
        let result = svc
            .compile_to_wasm(uuid::Uuid::nil(), uuid::Uuid::new_v4(), &name, &source)
            .await
            .with_context(|| format!("compile_to_wasm({name})"))?;
        let wasm = result
            .wasm_bytes
            .ok_or_else(|| anyhow::anyhow!("compile produced no WASM bytes for {name}"))?;

        let template_out = output_dir.join(&name);
        std::fs::create_dir_all(&template_out)?;
        std::fs::write(template_out.join("talos.json"), &manifest_str)?;
        std::fs::write(template_out.join("module.wasm"), &wasm)?;

        index_entries.push(serde_json::json!({"name": name, "tag": tag}));
        compiled += 1;
    }

    // Discovery index — must match registry::sync::IndexConfig shape exactly.
    // sync_once() pulls this artifact's config blob and parses it with that
    // struct; field renames here will silently break runtime sync.
    let index = serde_json::json!({"templates": index_entries});
    std::fs::write(
        output_dir.join("_index.json"),
        serde_json::to_string_pretty(&index)?,
    )?;

    eprintln!(
        "publish-templates: done — compiled {compiled} templates, skipped {skipped} \
         (missing talos.json or template.rs), wrote bundle to {}",
        output_dir.display()
    );
    Ok(())
}

// ---------- CORS Middleware ----------
/// MCP-1057 (2026-05-15): canonical CORS header values shared by every
/// CORS-response-emitting site (`cors_options`, `cors_middleware`'s
/// OPTIONS branch, and `cors_middleware`'s non-OPTIONS branch). Pre-fix
/// these three string literals were inlined at 3 sites with identical
/// content — same N-inline-copies drift class as MCP-1037..1056. Any
/// future change (add a new method, accept a new header, change the
/// preflight max-age) now lands in ONE place.
///
/// Comment on `CORS_ALLOW_METHODS`: explicitly restricted to methods
/// actually used by the API. PUT/DELETE are only called from
/// server-side code (not cross-origin browser requests), so omitting
/// them reduces the attack surface for CSRF.
const CORS_ALLOW_METHODS: &str = "GET, POST, OPTIONS";
const CORS_ALLOW_HEADERS: &str = "Content-Type, Authorization, X-API-Key, X-CSRF-Token";
const CORS_MAX_AGE: &str = "3600";

// MCP-1172 (2026-05-17): `resolve_allowed_origin` removed.
// Both consumers (`cors_options` + `cors_middleware`) now read the
// request's `Origin` header and check against
// `talos_config::is_allowed_origin` directly (MCP-1168 + MCP-1172),
// so the cached-single-string helper has no remaining users.
// `talos_config::ALLOWED_ORIGINS` is the canonical multi-value
// allowlist; reading the raw env at request-time was the source of
// the multi-origin ACAO drift bug that MCP-1168 closed.

async fn cors_middleware(req: Request<axum::body::Body>, next: Next) -> Response {
    use axum::http::Method;

    // MCP-1168 (2026-05-17): per-request Origin echo against the
    // talos_config::is_allowed_origin allowlist instead of
    // unconditionally binding the raw `ALLOWED_ORIGIN` env value.
    //
    // Pre-fix `resolve_allowed_origin()` returned the WHOLE
    // ALLOWED_ORIGIN string verbatim. For single-origin deployments
    // this worked; for multi-origin (`ALLOWED_ORIGIN=https://a.com,
    // https://b.com` — explicitly supported by talos_config's
    // ALLOWED_ORIGINS multi-value parsing AND by the
    // SECURITY-WARNING-on-multi log at talos-config/src/lib.rs:264)
    // the `Access-Control-Allow-Origin` response header became
    // `https://a.com,https://b.com` — invalid per RFC 6454 / CORS
    // spec, which requires exactly one origin when paired with
    // `Access-Control-Allow-Credentials: true` (set below). Browsers
    // reject the malformed value → CORS fails → multi-origin deploys
    // broke silently.
    //
    // Fix: read the request's Origin header, check against the
    // talos-config allowlist (which already splits on `,` and
    // validates scheme), echo it back if allowed, otherwise omit
    // the ACAO header entirely. Browsers without ACAO refuse the
    // cross-origin response — fail-closed for unknown origins.
    // `Vary: Origin` is added so caches don't serve a cached
    // allowed-origin response to a different-origin request.
    let request_origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let echoed_origin: Option<String> = request_origin
        .as_deref()
        .filter(|o| talos_config::is_allowed_origin(o))
        .map(|s| s.to_string());

    // Handle preflight OPTIONS requests immediately
    if req.method() == Method::OPTIONS {
        let mut response = Response::new(axum::body::Body::empty());
        *response.status_mut() = axum::http::StatusCode::OK;

        let headers = response.headers_mut();
        // MCP-1057: canonical CORS header consts.
        // MCP-1168: only set ACAO when the request's Origin is in
        // the allowlist. Browsers without ACAO refuse the response,
        // which is the correct CORS deny shape.
        if let Some(o) = &echoed_origin {
            if let Ok(v) = HeaderValue::from_str(o) {
                headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
            }
        }
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static(CORS_ALLOW_METHODS),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static(CORS_ALLOW_HEADERS),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static(CORS_MAX_AGE),
        );
        // MCP-1168: cache key MUST vary on Origin — without this a
        // CDN/proxy could serve a response with ACAO=https://a.com
        // to a subsequent request from https://b.com.
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));

        return response;
    }

    // For all other requests, process normally and add CORS headers to response
    let mut response = next.run(req).await;

    let headers = response.headers_mut();
    if let Some(o) = &echoed_origin {
        if let Ok(v) = HeaderValue::from_str(o) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
        }
    }
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(CORS_ALLOW_METHODS),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(CORS_ALLOW_HEADERS),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    // MCP-1168: append-or-set `Vary: Origin`. The security_headers
    // layer sets `Vary: Cookie` already; both must apply so caches
    // partition by both axes.
    match headers.get(header::VARY) {
        Some(existing)
            if existing.to_str().ok().is_some_and(|s| {
                s.split(',')
                    .any(|p| p.trim().eq_ignore_ascii_case("Origin"))
            }) =>
        {
            // Origin already in Vary — leave existing value untouched.
        }
        Some(existing) => {
            if let Ok(existing_str) = existing.to_str() {
                let combined = format!("{existing_str}, Origin");
                if let Ok(v) = HeaderValue::from_str(&combined) {
                    headers.insert(header::VARY, v);
                }
            }
        }
        None => {
            headers.insert(header::VARY, HeaderValue::from_static("Origin"));
        }
    }

    response
}

// ---------- Aggregate health check handler ----------
/// Comprehensive health check that reports on all subsystems (Postgres, Redis, NATS).
/// Returns 200 with `{"status":"ok"}` when all critical checks pass,
/// or 503 with `{"status":"degraded"}` when the database is unreachable.
/// Each sub-check has a 2-second timeout to avoid blocking the readiness probe.
///
/// SECURITY: Returns minimal information to prevent information leakage.
/// Detailed status is logged server-side only.
async fn health_check(
    Extension(db_pool): Extension<sqlx::PgPool>,
    Extension(redis_client): Extension<Option<std::sync::Arc<redis::Client>>>,
    Extension(nats_client): Extension<Option<std::sync::Arc<async_nats::Client>>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use serde_json::json;
    use std::time::Duration;

    let check_timeout = Duration::from_secs(2);

    // --- Database check (2s timeout) ---
    let db_ok = tokio::time::timeout(check_timeout, async {
        sqlx::query("SELECT 1").execute(&db_pool).await.is_ok()
    })
    .await
    .unwrap_or(false);

    // --- Redis check (2s timeout) ---
    let redis_ok = if let Some(ref client) = redis_client {
        tokio::time::timeout(check_timeout, async {
            match client.get_multiplexed_async_connection().await {
                Ok(mut conn) => redis::cmd("PING")
                    .query_async::<String>(&mut conn)
                    .await
                    .is_ok(),
                Err(_) => false,
            }
        })
        .await
        .unwrap_or(false)
    } else {
        // Not configured is not a failure
        true
    };

    // --- NATS check (2s timeout) ---
    let nats_ok = if let Some(ref client) = nats_client {
        tokio::time::timeout(check_timeout, async {
            client.connection_state() == async_nats::connection::State::Connected
        })
        .await
        .unwrap_or(false)
    } else {
        // Not configured is not a failure
        true
    };

    // Database is critical - if it's down, return 503
    // Redis/NATS are optional - if down but DB is up, return 200 with degraded status
    let (http_status, status_str) = if !db_ok {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, "degraded")
    } else if !redis_ok || !nats_ok {
        (axum::http::StatusCode::OK, "degraded")
    } else {
        (axum::http::StatusCode::OK, "ok")
    };

    // SECURITY: Log detailed status server-side only
    if !db_ok {
        tracing::error!("Health check: database connectivity failed");
    }
    if !redis_ok && redis_client.is_some() {
        tracing::warn!("Health check: Redis connectivity failed");
    }
    if !nats_ok && nats_client.is_some() {
        tracing::warn!("Health check: NATS connectivity failed");
    }

    // Return minimal information to prevent information leakage
    let body = json!({
        "status": status_str,
    });

    (http_status, axum::Json(body)).into_response()
}

// ---------- Redis health check endpoint ----------
async fn health_check_redis(
    Extension(redis_client): Extension<Option<std::sync::Arc<redis::Client>>>,
) -> Result<&'static str, axum::http::StatusCode> {
    if let Some(client) = redis_client {
        // Test Redis connection
        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!("Redis health check failed: connection error: {}", e);
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            })?;

        // Test PING command
        redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!("Redis health check failed: PING error: {}", e);
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            })?;

        Ok("OK")
    } else {
        tracing::warn!("Redis health check failed: client not configured");
        Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
    }
}

// ---------- NATS health check endpoint ----------
async fn health_check_nats(
    Extension(nats_client): Extension<Option<std::sync::Arc<async_nats::Client>>>,
) -> Result<&'static str, axum::http::StatusCode> {
    if let Some(client) = nats_client {
        // Test NATS connection by checking server info
        if client.connection_state() == async_nats::connection::State::Connected {
            Ok("OK")
        } else {
            tracing::error!("NATS health check failed: not connected");
            Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
        }
    } else {
        tracing::warn!("NATS health check failed: client not configured");
        Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
    }
}

// ---------- Kubernetes-style liveness probe ----------
/// Lightweight check that the process is responsive. Does NOT check subsystems.
/// Use for Kubernetes `livenessProbe` — if this fails, the pod should be restarted.
async fn liveness_probe() -> &'static str {
    "OK"
}

/// Seed the double-submit CSRF cookie for first-page-load. The frontend GETs
/// this once before its first POST `/graphql`; subsequent mutations rotate
/// the cookie via the regular csrf_protection_graphql middleware on
/// `graphql_routes`. Idempotent: returns 200 with no new cookie if the
/// client already presented one.
///
/// Builds the Set-Cookie header by hand so it doesn't depend on
/// CookieManagerLayer being wired in this router branch — relying on
/// layered cookies through merged sub-routers produced silent no-cookie
/// responses in production (root cause not pinned down; this handler
/// removes the indirection entirely).
async fn seed_csrf_handler(headers: axum::http::HeaderMap) -> axum::response::Response {
    use axum::http::{header, HeaderValue, StatusCode};
    use rand::RngCore;

    let already_has_cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            // Match either at the start or after a "; " — guards against a
            // cookie name that's a substring of another cookie's value.
            s.split(';')
                .any(|part| part.trim_start().starts_with("talos_csrf_token="))
        })
        .unwrap_or(false);

    let mut response = axum::response::Response::new(axum::body::Body::from("ok"));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    // MCP-582: per-session response with `Set-Cookie` of a unique
    // 32-byte CSRF token — MUST NOT be cached or shared between
    // clients. RFC 7234 forbids shared caches from serving Set-Cookie
    // responses to other clients by default, but operator-deployed
    // caches (CloudFlare, Varnish, nginx) can be misconfigured. Setting
    // `Cache-Control: no-store` is the explicit denial that all
    // RFC-compliant caches must honour. Also covers the "already has
    // cookie" branch where no Set-Cookie is issued but the response
    // body is still per-session-flow context. `Vary: Cookie` is
    // belt-and-suspenders: if a cache DOES try to cache despite
    // no-store, the Cookie request header becomes part of the cache
    // key so two users with different cookies never share an entry.
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Cookie"));

    if !already_has_cookie {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let token = hex::encode(bytes);

        // Frontend reads this cookie via JS to populate X-CSRF-Token, so it
        // CANNOT be HttpOnly. Secure in prod (HTTPS only), SameSite=Strict
        // mirrors what csrf::csrf_protection writes on the rotation path.
        let secure_attr = if config::is_production() {
            "; Secure"
        } else {
            ""
        };
        let value = format!("talos_csrf_token={token}; Path=/; SameSite=Strict{secure_attr}");

        match HeaderValue::from_str(&value) {
            Ok(v) => {
                response.headers_mut().insert(header::SET_COOKIE, v);
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "seed_csrf_handler: failed to encode Set-Cookie value"
                );
            }
        }
    }

    response
}

// ---------- Kubernetes-style readiness probe ----------
/// Full subsystem check: database (critical), Redis, NATS.
/// Use for Kubernetes `readinessProbe` — if this fails, the pod should be removed
/// from the load balancer but NOT restarted.
///
/// Returns 200 when the instance can serve traffic, 503 when it cannot.
async fn readiness_probe(
    Extension(db_pool): Extension<sqlx::PgPool>,
    Extension(redis_client): Extension<Option<std::sync::Arc<redis::Client>>>,
    Extension(nats_client): Extension<Option<std::sync::Arc<async_nats::Client>>>,
) -> Result<axum::response::Response, axum::response::Response> {
    use axum::response::IntoResponse;
    use serde_json::json;
    use std::time::Duration;

    let check_timeout = Duration::from_secs(2);

    // Database is mandatory — if it's down, the instance cannot serve traffic
    let db_ok = tokio::time::timeout(check_timeout, async {
        sqlx::query("SELECT 1").execute(&db_pool).await.is_ok()
    })
    .await
    .unwrap_or(false);

    if !db_ok {
        tracing::error!("Readiness probe: database connectivity failed");
        let body = json!({ "ready": false, "reason": "database_unavailable" });
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(body),
        )
            .into_response());
    }

    // Redis and NATS are optional — their absence degrades but doesn't block
    let redis_ok = if let Some(ref client) = redis_client {
        tokio::time::timeout(check_timeout, async {
            match client.get_multiplexed_async_connection().await {
                Ok(mut conn) => redis::cmd("PING")
                    .query_async::<String>(&mut conn)
                    .await
                    .is_ok(),
                Err(_) => false,
            }
        })
        .await
        .unwrap_or(false)
    } else {
        true
    };

    let nats_ok = if let Some(ref client) = nats_client {
        client.connection_state() == async_nats::connection::State::Connected
    } else {
        true
    };

    let body = json!({
        "ready": true,
        "subsystems": {
            "database": db_ok,
            "redis": redis_ok,
            "nats": nats_ok,
        }
    });

    Ok((axum::http::StatusCode::OK, axum::Json(body)).into_response())
}

// ---------- Prometheus scrape endpoint ----------
//
// Gated by a shared-secret `PROMETHEUS_SCRAPE_TOKEN` bearer — in K8s,
// this should only be reachable on an internal Service/port that the
// ServiceMonitor targets. Unauthenticated in dev only.
async fn prometheus_metrics_handler(
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, (axum::http::StatusCode, String)> {
    // MCP-591 (2026-05-12): treat empty-string env as "no token
    // configured". Pre-fix `PROMETHEUS_SCRAPE_TOKEN=""` produced
    // `Ok("")` → `expected = ""`, then `got.ct_eq(expected)` returned
    // true vacuously for any caller with a missing/empty bearer (got
    // defaults to "") — auth passed and the production fail-closed
    // path was skipped. Empty `expected` carries no entropy, so
    // route to the unset branch which fail-closes in production.
    // Sibling fix to MCP-590 in talos-registry.
    let configured = std::env::var("PROMETHEUS_SCRAPE_TOKEN")
        .ok()
        .filter(|v| !v.is_empty());
    if let Some(expected) = configured {
        use subtle::ConstantTimeEq as _;
        let got = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("");
        if got.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 0 {
            return Err((
                axum::http::StatusCode::UNAUTHORIZED,
                "invalid prometheus scrape token".to_string(),
            ));
        }
    } else if crate::config::is_production() {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            "PROMETHEUS_SCRAPE_TOKEN must be set in production".to_string(),
        ));
    }

    let m = metrics::global().ok_or_else(|| {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "metrics registry not initialised".to_string(),
        )
    })?;
    let body = m.render_prometheus().map_err(|e| {
        tracing::error!(error = %e, "prometheus render failed");
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "encoding failed".to_string(),
        )
    })?;
    let mut resp = axum::response::Response::new(axum::body::Body::from(body));
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    Ok(resp)
}

// ---------- Metrics endpoint ----------
async fn metrics_handler(
    Extension(db_pool): Extension<sqlx::PgPool>,
    Extension(schema): Extension<TalosSchema>,
    cookies: tower_cookies::Cookies,
    headers: axum::http::HeaderMap,
) -> Result<impl axum::response::IntoResponse, (axum::http::StatusCode, String)> {
    use serde_json::json;

    // Extract token from cookie or Authorization header
    let token = cookies
        .get("talos_access_token")
        .map(|c| c.value().to_string())
        .or_else(|| {
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer ").map(|t| t.to_string()))
        })
        .ok_or_else(|| {
            (
                axum::http::StatusCode::UNAUTHORIZED,
                "Authentication required (cookie or Bearer token)".to_string(),
            )
        })?;

    // Verify token and extract user_id
    let auth_service = schema
        .data::<std::sync::Arc<AuthService>>()
        .ok_or_else(|| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Auth service not available".to_string(),
            )
        })?;

    let claims = auth_service.verify_token(&token).map_err(|_| {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            "Invalid or expired token".to_string(),
        )
    })?;

    let user_id = uuid::Uuid::parse_str(&claims.sub).map_err(|_| {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            "Invalid user ID in token".to_string(),
        )
    })?;

    // Gather user-specific metrics
    let webhook_stats = sqlx::query_as::<_, (i64, i64, i64, i64, f64)>(
        r#"
        SELECT
            COUNT(*)::bigint,
            COALESCE(SUM(trigger_count), 0)::bigint,
            COALESCE(SUM(success_count), 0)::bigint,
            COALESCE(SUM(error_count), 0)::bigint,
            COALESCE(AVG(avg_response_ms), 0.0)::float
        FROM webhook_triggers
        WHERE user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_one(&db_pool)
    .await
    .map_err(|e| {
        tracing::error!(user_id = %user_id, error = %e, "Failed to fetch webhook stats");
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to fetch metrics".to_string(),
        )
    })?;

    // MCP-676 (2026-05-13): the `secrets` table has THREE legacy
    // ownership columns from drift across the early schema: `user_id`
    // (001_initial_schema, never written by any code path),
    // `created_by` (001_initial_schema, written by `INSERT INTO
    // secrets` in talos-secrets-manager), and `owner_user_id`
    // (007_missing_columns, backfilled from created_by in
    // 20260410100005). The CANONICAL column is `owner_user_id` —
    // every write site sets both `created_by` and `owner_user_id`
    // to the creating user; nothing populates `user_id`. Pre-fix the
    // user-stats endpoint queried `WHERE user_id = $1` and silently
    // returned (count=0, sum=0) for every user regardless of how
    // many secrets they actually owned. UX bug, not a security bug
    // — but the broken column reference is a copy-paste hazard for
    // future code and worth fixing alongside the equivalent
    // talos-workflow-repository::get_provisioned_secrets gap.
    let secret_stats = sqlx::query_as::<_, (i64, i64)>(
        r#"
        SELECT
            COUNT(*)::bigint,
            COALESCE(SUM(access_count), 0)::bigint
        FROM secrets
        WHERE owner_user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_one(&db_pool)
    .await
    .map_err(|e| {
        tracing::error!(user_id = %user_id, error = %e, "Failed to fetch secret stats");
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to fetch metrics".to_string(),
        )
    })?;

    // Phase 5: reads from the unified `modules` table (filter to user-authored
    // sandbox/extracted rows so catalog counts don't double-count per user).
    let module_stats = sqlx::query_as::<_, (i64, i64, i64)>(
        r#"
        SELECT
            COUNT(*)::bigint,
            COALESCE(SUM(usage_count), 0)::bigint,
            COALESCE(SUM(size_bytes), 0)::bigint
        FROM modules
        WHERE user_id = $1 AND kind IN ('sandbox', 'extracted')
        "#,
    )
    .bind(user_id)
    .fetch_one(&db_pool)
    .await
    .map_err(|e| {
        tracing::error!(user_id = %user_id, error = %e, "Failed to fetch module stats");
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to fetch metrics".to_string(),
        )
    })?;

    let metrics = json!({
        "status": "healthy",
        "webhooks": {
            "total_listeners": webhook_stats.0,
            "total_triggers": webhook_stats.1,
            "total_successes": webhook_stats.2,
            "total_errors": webhook_stats.3,
            "avg_response_time_ms": webhook_stats.4,
        },
        "secrets": {
            "total_secrets": secret_stats.0,
            "total_accesses": secret_stats.1,
        },
        "modules": {
            "total_modules": module_stats.0,
            "total_executions": module_stats.1,
            "total_size_mb": (module_stats.2 as f64 / 1_048_576.0),
        },
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    Ok(axum::Json(metrics))
}

// ---------- REST API Authentication Middleware ----------
async fn rest_auth_middleware(
    cookies: tower_cookies::Cookies,
    headers: axum::http::HeaderMap,
    Extension(auth_service): Extension<std::sync::Arc<AuthService>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, axum::http::StatusCode> {
    // MCP-531: log COOKIE-header PRESENCE only — never its value.
    //
    // Pre-fix this site emitted `Cookie header: {:?}` at debug level,
    // which prints the entire Cookie header via `HeaderValue::Debug`.
    // The Cookie header carries JWT access + refresh tokens
    // (`talos_access_token=eyJ…`, `talos_refresh_token=eyJ…`), so any
    // operator running with `RUST_LOG=debug` (common in dev, used in
    // production for transient troubleshooting) was writing every
    // request's session credentials into the log aggregator verbatim.
    //
    // Per CLAUDE.md "Security Rules": NEVER log sensitive values
    // (tokens, cookies, API keys, secrets). Log presence only.
    tracing::debug!(
        cookie_header_present = headers.contains_key(axum::http::header::COOKIE),
        "REST auth middleware - cookie header presence",
    );

    // Insert the request headers into extensions for downstream handlers that may need them
    req.extensions_mut().insert(headers.clone());

    // Try to get token from cookie first, then fall back to Authorization header.
    // Logs presence only — never any token material, even truncated.
    // talos_access_token is a JWT today (header bytes are non-secret) but a
    // truncated-prefix log is still a footgun the next time the format
    // changes, and "cookie token present" is the only diagnostic this
    // path needs.
    let token = cookies
        .get("talos_access_token")
        .map(|c| {
            tracing::debug!("REST auth - cookie token present");
            c.value().to_string()
        })
        .or_else(|| {
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| {
                    s.strip_prefix("Bearer ").map(|t| {
                        tracing::debug!("REST auth - Found Bearer token");
                        t.to_string()
                    })
                })
        });

    if token.is_none() {
        tracing::debug!("REST auth - No token found in cookies or headers");
        tracing::debug!("REST auth - Returning 401");
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }

    // Verify token
    if let Some(token_str) = token {
        if let Ok(claims) = auth_service.verify_token(&token_str) {
            if let Ok(user_id) = uuid::Uuid::parse_str(&claims.sub) {
                // MCP-587 (2026-05-12): enforce 2FA at the REST
                // middleware boundary. Pre-fix this middleware verified
                // the token but ignored `claims.is_2fa_verified` — a
                // pre-2FA token (issued by login when the user has TOTP
                // enabled but hasn't completed verify_two_factor yet)
                // sailed through every REST endpoint behind this
                // middleware: approval gates, Slack app creation, Gmail
                // / Slack integration management.
                //
                // The OAuth callback comment at line ~5141 explicitly
                // warns about exactly this bypass class — "Hardcoding
                // `true` here would bypass 2FA for anyone who can
                // complete an OAuth handshake … i.e. Google-account
                // compromise = Talos session, even when the user thinks
                // TOTP is protecting them." Same bypass shape, just at
                // the REST entry point instead of the OAuth one.
                //
                // GraphQL injects `IsTwoFactorVerified` into the
                // request context so resolvers can decide; REST has no
                // resolver layer so the middleware is the only gate.
                // Fail-closed: reject with 403 + structured message
                // pointing the caller at the 2FA-verification endpoint.
                if !claims.is_2fa_verified {
                    tracing::warn!(
                        user_id = %user_id,
                        "REST auth: pre-2FA token rejected — caller must complete TOTP verification before reaching REST endpoints"
                    );
                    return Err(axum::http::StatusCode::FORBIDDEN);
                }
                tracing::debug!(
                    "REST auth - Authenticated user {}, inserting into extensions",
                    user_id
                );
                // Insert user_id into request extensions so handlers can extract it
                req.extensions_mut().insert(user_id);
                tracing::debug!("REST auth - Extension inserted, calling next");
                let response = next.run(req).await;
                tracing::debug!("REST auth - Handler completed");
                return Ok(response);
            } else {
                tracing::debug!("REST auth - Invalid user_id in claims");
            }
        } else {
            tracing::debug!("REST auth - Token verification failed");
        }
    }

    // If no valid authentication, return 401
    tracing::debug!("REST auth - Returning 401");
    Err(axum::http::StatusCode::UNAUTHORIZED)
}

// ---------- GraphQL HTTP handler ----------
async fn graphql_handler(
    ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    schema: Extension<TalosSchema>,
    cookies: tower_cookies::Cookies,
    headers: axum::http::HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let mut req = req.into_inner();

    // Extract the REAL client IP via the RFC-7239 trusted-proxy walk — NOT the
    // raw socket peer. Behind the chart's nginx frontend, `addr.ip()` is the
    // proxy pod IP for every request; using it here collapses ALL login/signup/
    // refresh/2FA traffic onto a single shared auth-limiter bucket (the auth
    // limiter is a hardcoded 5/min keyed on this `ip_address`), so 6 attempts a
    // minute from anywhere would 429 the entire platform's login surface — a
    // trivial unauthenticated DoS — and every audit-log row would record the
    // proxy IP instead of the attacker. Mirrors the MCP-1097 fix in
    // `mcp_auth_middleware`. `extract_client_ip` rejects XFF spoofing and, when
    // the peer is NOT a trusted proxy (direct-connection deploys), returns the
    // peer IP unchanged — so this is regression-free outside a proxy topology.
    static TRUSTED_PROXIES: std::sync::LazyLock<rate_limit::TrustedProxies> =
        std::sync::LazyLock::new(rate_limit::TrustedProxies::from_env);
    let ip_address =
        Some(rate_limit::extract_client_ip(addr.ip(), &headers, &TRUSTED_PROXIES).to_string());

    // Extract user agent
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Create request metadata for audit logging
    let metadata = api::schema::RequestMetadata {
        ip_address,
        user_agent,
    };

    // Inject metadata into GraphQL context
    req = req.data(metadata);

    // Try to get token from cookie first, then fall back to Authorization header
    let token = cookies
        .get("talos_access_token")
        .map(|c| c.value().to_string())
        .or_else(|| {
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer ").map(|t| t.to_string()))
        });

    // Inject Cookies into GraphQL context for mutations to set cookies
    req = req.data(cookies);

    // Try API key authentication first (X-API-Key header)
    // MERELY presenting the header commits the request to the API-key lane:
    // a present-but-invalid key fails CLOSED (below), it is NOT downgraded to
    // the ambient session cookie. This is the security pairing for the CSRF
    // exemption in `talos-csrf::is_api_key_request` — CSRF is skipped for
    // X-API-Key requests, so if a bogus key could silently fall back to the
    // victim's cookie, an attacker's cross-origin page could send a junk
    // X-API-Key to bypass CSRF and ride the session. Failing closed removes
    // that path.
    let api_key_header_present = headers.contains_key("X-API-Key");
    let mut authenticated = false;
    // Tracks a JWT session that authenticated but has NOT completed 2FA
    // (password-only). API keys are always 2FA-verified; unauthenticated
    // requests stay `false` so the login/signup flow keeps working.
    let mut pre_2fa_session = false;
    if let Some(api_key) = headers.get("X-API-Key").and_then(|h| h.to_str().ok()) {
        // Get API key service from schema data
        if let Some(api_key_service) = schema.0.data::<std::sync::Arc<api_keys::ApiKeyService>>() {
            if let Ok((user_id, scopes)) = api_key_service.validate_key(api_key).await {
                // Inject user_id into GraphQL context
                req = req.data(user_id);
                // Inject scopes so resolvers can enforce fine-grained authorization.
                // JWT-authenticated requests do NOT inject ApiKeyScopes, so the absence
                // of this data in context signals "full access via session token".
                req = req.data(crate::api::schema::ApiKeyScopes(scopes));
                // API keys skip 2FA
                req = req.data(crate::api::schema::IsTwoFactorVerified(true));
                authenticated = true;
                tracing::debug!("Authenticated via API key for user {}", user_id);
            } else {
                tracing::debug!(
                    "X-API-Key present but invalid — failing closed (no cookie fallback)"
                );
            }
        }
    }

    // Fall back to JWT token authentication ONLY when no API key was
    // presented. See the api_key_header_present rationale above.
    if !authenticated && !api_key_header_present {
        if let Some(token_str) = token {
            // Get auth service from schema data
            if let Some(auth_service) = schema.0.data::<std::sync::Arc<AuthService>>() {
                if let Ok(claims) = auth_service.verify_token(&token_str) {
                    if let Ok(user_id) = uuid::Uuid::parse_str(&claims.sub) {
                        // Inject user_id into GraphQL context
                        req = req.data(user_id);
                        // Inject 2FA verification status
                        req = req.data(crate::api::schema::IsTwoFactorVerified(
                            claims.is_2fa_verified,
                        ));
                        pre_2fa_session = !claims.is_2fa_verified;
                        tracing::debug!(
                            "Authenticated via JWT for user {} (2FA verified: {})",
                            user_id,
                            claims.is_2fa_verified
                        );
                    }
                }
            }
        }
    }

    // Security review 2026-07-19 (P3): a password-verified but TOTP-pending
    // session may only run the 2FA-completion / bootstrap operations. This is
    // the read-surface counterpart to `require_2fa` on mutations and the REST
    // middleware's pre-2FA 403 — without it, a pre-2FA JWT could read the whole
    // GraphQL query surface (workflows, executions, decrypted agent memory,
    // secret metadata). Fails closed on unparseable/ambiguous operations.
    if pre_2fa_session
        && !api::schema::pre_2fa_operation_allowed(&req.query, req.operation_name.as_deref())
    {
        tracing::debug!("Refused pre-2FA GraphQL operation (2FA not completed)");
        return GraphQLResponse::from(async_graphql::Response::from_errors(vec![
            async_graphql::ServerError::new(
                "Two-Factor Authentication required. Complete 2FA verification to \
                 access this resource.",
                None,
            ),
        ]));
    }

    let mut response = schema.execute(req).await;

    // Scrub internal error details in all non-development environments
    // (production, staging, test, etc.) to avoid leaking sensitive information.
    //
    // Two-layer policy:
    //   1. EXPLICIT MARKER (preferred). Resolvers that want a user-facing
    //      error message call `.extend_safe()` which sets `extensions.safe
    //      = true`. Any error with that marker passes through verbatim.
    //      `api/schema/mod.rs::is_safe_error` is the canonical reader.
    //   2. SUBSTRING FALLBACK. Older paths haven't been migrated to
    //      `.extend_safe()` yet — keep them whitelisted by message
    //      content so a refactor doesn't accidentally start scrubbing
    //      legitimate errors. New code MUST use `.extend_safe()` rather
    //      than relying on substring matches.
    //
    // Errors that match neither layer get replaced with the generic
    // "Internal server error" string. The full original error is logged
    // server-side via `tracing::error!` for debugging.
    if !config::is_development() {
        for error in &mut response.errors {
            tracing::error!("GraphQL Error: {:?}", error);

            if crate::api::schema::is_safe_error(error) {
                continue; // explicitly marked safe — keep verbatim
            }

            // MCP-1051 (2026-05-15): route through canonical
            // `is_safe_error_substring` helper. Pre-fix the
            // whitelist substrings were inlined here AND in
            // `scripts/lint-structural.sh::check 14` — two copies
            // that could drift if a future change adds/removes a
            // substring on only one side. The const + helper in
            // talos-api/src/schema/mod.rs is now the single source
            // of truth for the scrubber path; the lint still
            // hardcodes the list but the const documents itself as
            // the parity reference.
            let msg = error.message.as_str();
            if !crate::api::schema::is_safe_error_substring(msg) {
                error.message = "Internal server error".to_string();
            }
        }
    }

    response.into()
}

// ---------- GraphQL Playground ----------
async fn graphql_playground() -> impl axum::response::IntoResponse {
    axum::response::Html(async_graphql::http::graphiql_source(
        "/graphql",
        Some("/ws"),
    ))
}

// ---------- WebSocket Handler with Authentication ----------
async fn websocket_handler(
    ws: WebSocketUpgrade,
    cookies: tower_cookies::Cookies,
    headers: axum::http::HeaderMap,
    Extension(schema): Extension<TalosSchema>,
    Extension(auth_service): Extension<std::sync::Arc<AuthService>>,
) -> Response {
    // Extract access token from cookie (secure: httpOnly cookie, not JavaScript)
    let access_token = cookies
        .get("talos_access_token")
        .map(|c| c.value().to_string());

    // Origin is captured from the upgrade request and validated inside
    // `handle_websocket_auth` to defend against Cross-Site WebSocket
    // Hijacking. Browsers always send Origin on WS handshakes; reverse
    // proxies must forward it (see chart nginx /ws location).
    let origin = headers.get(axum::http::header::ORIGIN).cloned();

    // MCP-1039: cap inbound WS message size. Default tungstenite limit
    // is 64 MiB per message / 16 MiB per frame — any authenticated
    // client can ship 64 MiB Text frames that the GraphQL handler then
    // serde_json-parses (O(N)). Legitimate graphql-ws control frames
    // (connection_init, subscribe, complete, ping) and the largest
    // expected subscription event (execution_updates with per-node
    // output) all fit comfortably under 1 MiB. Sibling defense-in-depth
    // to MCP-1014 (WIT outbound body cap) and MCP-1013 (XML/JSON input
    // cap) — every caller-controlled byte boundary on the controller
    // needs an explicit cap appropriate to the protocol, not the
    // upstream library's default.
    ws.max_message_size(1024 * 1024)
        .max_frame_size(1024 * 1024)
        .protocols(["graphql-ws"])
        .on_upgrade(move |socket| {
            ws_auth::handle_websocket_auth(socket, schema, auth_service, access_token, origin)
        })
}

// ---------- Seed templates ----------

/// Upsert a single built-in template.
///
/// Always updates `code_template` and `config_schema` so that rebuilding the
/// controller binary (which embeds templates via `include_str!`) keeps the DB
/// in sync without a manual DB wipe.  `category`, `description`, and `icon`
/// are only written on first insert.
async fn seed_templates(
    registry: &std::sync::Arc<ModuleRegistry>,
    compiler: std::sync::Arc<CompilationService>,
) -> anyhow::Result<()> {
    // Mutually exclusive with OCI registry sync. When `TALOS_REGISTRY_URL` is
    // set, the registry is the single source of truth — disk seeding would
    // race the OCI sync loop on every pod restart, briefly overwriting
    // operator-curated template versions with the disk baseline before the
    // 5-minute sync replaces them again.
    //
    // MCP-598 (2026-05-12): treat empty-env as unset. Pre-fix
    // `TALOS_REGISTRY_URL=""` matched `.is_ok()`, skipping disk seed,
    // while the OCI sync (`talos-registry::sync.rs`) failed to parse the
    // empty URL → no templates loaded at all. Helm values.yaml
    // placeholders (`registryUrl: ""`) hit this footgun routinely.
    // Sibling fix to MCP-597 (read_env_or_file empty handling).
    let has_registry_url = std::env::var("TALOS_REGISTRY_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .is_some();
    if has_registry_url {
        tracing::info!(
            "TALOS_REGISTRY_URL set — disk template seeding disabled. \
             OCI registry is the source of truth."
        );
        return Ok(());
    }

    let templates_dir = std::path::Path::new("module-templates");
    if !templates_dir.exists() {
        tracing::info!("No module-templates/ directory found — skipping template seeding");
        return Ok(());
    }

    let mut count = 0u32;
    let entries = std::fs::read_dir(templates_dir)
        .map_err(|e| anyhow::anyhow!("Failed to read module-templates directory: {}", e))?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("Failed to read directory entry: {}", e);
                continue;
            }
        };
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let manifest_path = path.join("talos.json");
        if !manifest_path.exists() {
            continue;
        }

        let manifest_str = match std::fs::read_to_string(&manifest_path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Failed to read {}: {}", manifest_path.display(), e);
                continue;
            }
        };

        let manifest: serde_json::Value = match serde_json::from_str(&manifest_str) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Failed to parse {}: {}", manifest_path.display(), e);
                continue;
            }
        };

        let name = manifest
            .get("display_name")
            .or_else(|| manifest.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let category = manifest
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("General")
            .to_string();
        let description = manifest
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let config_schema = manifest
            .get("config_schema")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let allowed_hosts: Vec<String> = manifest
            .get("allowed_hosts")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if let Err(msg) = crate::registry::validate_allowed_hosts(&allowed_hosts) {
            tracing::warn!(
                "Skipping template '{}': invalid allowed_hosts: {}",
                name,
                msg
            );
            continue;
        }
        let allowed_secrets: Vec<String> = manifest
            .get("requires_secrets")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        // MCP-1125 (2026-05-16): sibling sweep of MCP-1124 to the
        // third ingest boundary. The talos-registry api.rs and sync.rs
        // paths got `validate_allowed_secrets` in MCP-1124; this
        // disk-seeding path that ingests `module-templates/*/talos.json`
        // at controller startup was the holdout. Same threat:
        // a malformed `talos.json` (operator mistake or compromised
        // image build) could persist garbage entries that the
        // `vault_path_permitted` matcher then runs against on every
        // secret-resolution call from the templated module. Skip the
        // template (don't bail the whole startup loop) — the
        // controller still boots; the bad template just isn't seeded.
        if let Err(msg) = crate::registry::validate_allowed_secrets(&allowed_secrets) {
            tracing::warn!(
                "Skipping template '{}': invalid allowed_secrets: {}",
                name,
                msg
            );
            continue;
        }
        let requires_approval_for: Vec<String> = manifest
            .get("requires_approval_for")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        // Read the code template if available
        let code_template = std::fs::read_to_string(path.join("template.rs"))
            .or_else(|_| std::fs::read_to_string(path.join("src/lib.rs")))
            .unwrap_or_default();

        if name.is_empty() {
            continue;
        }

        // Phase 5: detect whether the on-disk source differs from the
        // persisted `modules.source_code` so we can trigger a background
        // recompile after the upsert. IS DISTINCT FROM handles NULL-safe
        // comparison correctly.
        let stale_id: Option<uuid::Uuid> = sqlx::query_scalar(
            "SELECT id FROM modules \
             WHERE name = $1 AND user_id IS NULL \
               AND source_code IS DISTINCT FROM $2",
        )
        .bind(&name)
        .bind(&code_template)
        .fetch_optional(&registry.db_pool)
        .await
        .unwrap_or(None);

        // Read capability_world from talos.json; default to 'automation-node' when absent
        // so unknown modules get maximum restriction (safest default for new templates).
        let capability_world = manifest
            .get("capability_world")
            .and_then(|v| v.as_str())
            .unwrap_or("automation-node")
            .to_string();
        // modules.capability_world is stored in long form to match the
        // worker-side CapabilityWorld parser. The talos.json convention
        // already uses the `-node` suffix but guard defensively.
        let cw_long = if capability_world == "trusted" {
            "automation-node".to_string()
        } else if capability_world.ends_with("-node") {
            capability_world.clone()
        } else {
            format!("{}-node", capability_world)
        };

        // Phase 5: seed the unified `modules` table directly with
        // `kind = 'catalog'` + `user_id IS NULL`. Matches the partial
        // unique index `modules_catalog_name_uniq` so catalog entries keep
        // a stable UUID across rebuilds. Mirrors the registry::api and
        // registry::sync catalog-publish paths.
        let result: Result<uuid::Uuid, _> = sqlx::query_scalar(
            "INSERT INTO modules ( \
                 user_id, name, kind, category, description, config_schema, \
                 source_code, allowed_hosts, allowed_secrets, requires_approval_for, \
                 capability_world, catalog_slug, language, created_at, updated_at \
             ) VALUES ( \
                 NULL, $1, 'catalog', $2, $3, $4, \
                 $5, $6, $7, $8, \
                 $9, $10, 'rust', NOW(), NOW() \
             ) \
             ON CONFLICT (name) WHERE user_id IS NULL DO UPDATE SET \
                 category              = EXCLUDED.category, \
                 catalog_slug          = EXCLUDED.catalog_slug, \
                 description           = EXCLUDED.description, \
                 config_schema         = EXCLUDED.config_schema, \
                 source_code           = EXCLUDED.source_code, \
                 allowed_hosts         = EXCLUDED.allowed_hosts, \
                 allowed_secrets       = EXCLUDED.allowed_secrets, \
                 requires_approval_for = EXCLUDED.requires_approval_for, \
                 capability_world      = EXCLUDED.capability_world, \
                 updated_at            = NOW() \
             RETURNING id",
        )
        .bind(&name)
        .bind(&category)
        .bind(&description)
        .bind(&config_schema)
        .bind(&code_template)
        .bind(&allowed_hosts)
        .bind(&allowed_secrets)
        .bind(&requires_approval_for)
        .bind(&cw_long)
        .bind(path.file_name().and_then(|f| f.to_str()))
        .fetch_one(&registry.db_pool)
        .await;

        match result {
            Ok(template_id) => {
                count += 1;
                // If source_code changed, spawn a background task to
                // recompile and update `modules.wasm_bytes` once the new
                // binary is ready. Existing compiled rows for user sandboxes
                // are intentionally preserved — workflows already running
                // against old compiled binaries must not be broken across a
                // server restart. They will pick up the new template the
                // next time the user explicitly recompiles their module.
                if stale_id.is_some() {
                    let pool_bg = registry.db_pool.clone();
                    let compiler_bg = compiler.clone();
                    let name_bg = name.clone();
                    let code_bg = code_template.clone();
                    let tid = template_id;
                    tokio::spawn(async move {
                        tracing::info!(
                            template = %name_bg,
                            "Template source changed — background recompilation started"
                        );
                        match compiler_bg
                            .compile_to_wasm(
                                uuid::Uuid::nil(),
                                uuid::Uuid::new_v4(),
                                &name_bg,
                                &code_bg,
                            )
                            .await
                        {
                            Ok(result) if result.success => {
                                if let Some(wasm_bytes) = result.wasm_bytes {
                                    let bytes_len = wasm_bytes.len();
                                    use sha2::{Digest, Sha256};
                                    let hash = format!("{:x}", Sha256::digest(&wasm_bytes));
                                    match sqlx::query(
                                        "UPDATE modules \
                                         SET wasm_bytes = $1, content_hash = $2, \
                                             size_bytes = $3, compiled_at = NOW(), \
                                             updated_at = NOW() \
                                         WHERE id = $4",
                                    )
                                    .bind(&wasm_bytes)
                                    .bind(&hash)
                                    .bind(bytes_len as i32)
                                    .bind(tid)
                                    .execute(&pool_bg)
                                    .await
                                    {
                                        Ok(_) => tracing::info!(
                                            template = %name_bg,
                                            bytes = bytes_len,
                                            "Background recompilation complete — modules.wasm_bytes updated"
                                        ),
                                        Err(e) => tracing::warn!(
                                            template = %name_bg,
                                            error = %e,
                                            "Background recompilation succeeded but DB update failed"
                                        ),
                                    }
                                }
                            }
                            Ok(result) => {
                                tracing::warn!(
                                    template = %name_bg,
                                    errors = ?result.errors,
                                    "Background recompilation failed — keeping existing wasm_bytes"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    template = %name_bg,
                                    error = %e,
                                    "Background recompilation error — keeping existing wasm_bytes"
                                );
                            }
                        }
                    });
                }
            }
            Err(e) => tracing::warn!("Failed to seed template '{}': {}", name, e),
        }
    }

    tracing::info!("Seeded {} module templates from disk", count);
    Ok(())
}

/// Publish first-party catalog modules to module_marketplace that aren't already listed.
///
/// Phase 5: sources from the unified `modules` table filtered to
/// `kind = 'catalog' AND user_id IS NULL` — excludes user-compiled sandbox
/// entries, extracted inline modules, QA fixtures, and installed marketplace
/// clones which all carry a non-NULL user_id. publisher_id = nil UUID (system).
/// verified = true. Idempotent via NOT EXISTS.
///
/// First removes any previously-published system entries whose backing module
/// is no longer catalog-scope (i.e. stale rows from before the Phase 5 schema
/// unification when QA/sandbox entries could sneak into marketplace).
async fn seed_marketplace(pool: &sqlx::PgPool) {
    // Step 1: Remove stale system-published entries that point to sandbox / QA modules.
    // Only touches rows where publisher_id = nil UUID (system-published).
    match sqlx::query(
        "DELETE FROM module_marketplace mm
         WHERE mm.publisher_id = '00000000-0000-0000-0000-000000000000'::uuid
           AND EXISTS (
               SELECT 1 FROM modules m
               WHERE m.id = mm.module_id
                 AND (
                     m.kind != 'catalog'
                     OR m.user_id IS NOT NULL
                     OR m.name IS NULL
                     OR m.description IS NULL
                     OR m.description = ''
                 )
           )",
    )
    .execute(pool)
    .await
    {
        Ok(r) => tracing::info!(
            "seed_marketplace: removed {} stale sandbox/QA entries from marketplace",
            r.rows_affected()
        ),
        Err(e) => tracing::warn!("seed_marketplace cleanup: {}", e),
    }

    // Step 2: Publish first-party catalog modules not yet listed.
    // Phase 5.1: canonical modules.id only. Dedup on (name, version)
    // rather than module_id because pre-5.0 runs published with
    // `COALESCE(legacy_template_id, m.id)` which for catalog modules
    // resolved to the legacy template id — different from m.id but
    // same (name, version), so a module_id-only EXISTS check would
    // miss those rows and trip the unique constraint.
    match sqlx::query(
        "INSERT INTO module_marketplace
             (id, module_id, publisher_id, name, description, capability_world,
              version, is_public, tags, verified)
         SELECT
             gen_random_uuid(), m.id,
             '00000000-0000-0000-0000-000000000000'::uuid,
             m.name, m.description, m.capability_world,
             '1.0.0', true, ARRAY[]::text[], true
         FROM modules m
         WHERE m.kind = 'catalog'
           AND m.user_id IS NULL
           AND m.name IS NOT NULL
           AND m.description IS NOT NULL
           AND m.description != ''
           AND NOT EXISTS (
               SELECT 1 FROM module_marketplace mm
               WHERE mm.name = m.name AND mm.version = '1.0.0'
           )",
    )
    .execute(pool)
    .await
    {
        Ok(r) => tracing::info!(
            "seed_marketplace: published {} first-party templates to marketplace",
            r.rows_affected()
        ),
        Err(e) => tracing::warn!("seed_marketplace: {}", e),
    }
}

// ---------- OAuth handlers ----------

#[derive(serde::Deserialize)]
pub struct OAuthLoginQuery {
    scopes: Option<String>,
}

/// Initiate OAuth login flow
async fn oauth_login_handler(
    axum::extract::Path(provider): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<OAuthLoginQuery>,
    Extension(oauth_service): Extension<std::sync::Arc<OAuthService>>,
    cookies: tower_cookies::Cookies,
) -> Result<impl axum::response::IntoResponse, (axum::http::StatusCode, String)> {
    use axum::response::Redirect;

    let provider = OAuthProvider::from_str(&provider).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            format!("Invalid provider: {}", e),
        )
    })?;

    let extra_scopes: Option<Vec<String>> = query
        .scopes
        .map(|s| s.split(',').map(|s| s.to_string()).collect());
    // MCP-995 (2026-05-15): log full error server-side, return a
    // generic message to the client. Pre-fix the body echoed
    // `e: anyhow::Error` verbatim — `get_authorization_url` errors
    // include:
    //   * "X OAuth is not configured. Set environment variables."
    //     (leaks operator config state to an unauthenticated endpoint)
    //   * Underlying Redis errors from `store_state_token` (connection
    //     state, auth failures)
    // CLAUDE.md security rule: "NEVER return internal error details to
    // API clients. Log full errors server-side, return generic
    // messages." Same rule MCP-275/581 applied to OAuth callback paths
    // in talos-atlassian / gmail / slack / google_calendar handlers —
    // extend the same discipline to the controller's
    // `/auth/oauth/{provider}/login` initiator.
    let provider_for_log = format!("{:?}", provider);
    let (auth_url, _csrf_token, session_nonce) = oauth_service
        .get_authorization_url(provider, extra_scopes)
        .await
        .map_err(|e| {
            tracing::error!(
                provider = %provider_for_log,
                error = %e,
                "OAuth login: failed to generate auth URL"
            );
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "OAuth login unavailable. Contact your administrator.".to_string(),
            )
        })?;

    // S1 (login-CSRF / session-fixation defense): bind the OAuth `state`
    // nonce to THIS browser. `get_authorization_url` persisted only the
    // SHA-256 of `session_nonce`; we hand the plaintext back to the browser
    // as an HttpOnly cookie and require it to match on the callback
    // (`handle_callback` → `validate_state_token`). Without this, a valid
    // `state` proves only "Talos issued this URL", not "issued to this
    // browser" — the classic OAuth login-CSRF hole. Cookie attributes are
    // centralised in talos-api so the REST + GraphQL login paths stay in
    // lockstep (see `set_oauth_session_binding_cookie`).
    talos_api::schema::auth::set_oauth_session_binding_cookie(&cookies, &session_nonce);

    // Redirect to OAuth provider.
    Ok(Redirect::temporary(&auth_url))
}

/// Handle OAuth callback
async fn oauth_callback_handler(
    axum::extract::Path(provider): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    Extension(oauth_service): Extension<std::sync::Arc<OAuthService>>,
    Extension(auth_service): Extension<std::sync::Arc<AuthService>>,
    Extension(google_calendar_service): Extension<
        std::sync::Arc<google_calendar::GoogleCalendarService>,
    >,
    cookies: tower_cookies::Cookies,
) -> std::result::Result<impl axum::response::IntoResponse, axum::http::StatusCode> {
    use axum::response::Redirect;
    // MCP-1040: `tower_cookies::Cookie` no longer used directly — the
    // canonical `set_session_cookies` helper handles cookie construction.

    let provider_enum =
        OAuthProvider::from_str(&provider).map_err(|_e| axum::http::StatusCode::BAD_REQUEST)?;

    // Extract authorization code and state parameter
    //
    // MCP-623 (2026-05-12): route through `talos_config::get_frontend_url()`
    // so the empty-env-var bug class (MCP-615 sibling) doesn't apply. Pre-fix
    // `env::var("FRONTEND_URL").unwrap_or_else(|_| default)` returned `""`
    // for an empty env value, then `format!("{}/auth/callback?...", "")`
    // produced a leading-slash relative redirect. Browsers interpret that
    // as same-origin, so single-host deployments survive but split-origin
    // deployments redirect users to the controller host's `/auth/callback`
    // instead of the frontend. Helm `values.yaml` placeholder
    // `frontendUrl: ""` would have hit this. The helper now applies the
    // canonical `.ok().filter(|v| !v.is_empty())` shape (MCP-615) so empty
    // values fall through to the documented `http://localhost:3000` default.
    let frontend_url = talos_config::get_frontend_url();

    let code = match params.get("code") {
        Some(c) => c,
        None => {
            let error_msg = params
                .get("error")
                .map(|s| s.as_str())
                .unwrap_or("missing_code");
            tracing::warn!("OAuth callback missing code. Error: {}", error_msg);
            // MCP-1094: sanitise provider-supplied error before
            // reflecting into the dashboard redirect URL.
            let safe_error = talos_config::sanitize_oauth_error_code(error_msg);
            return Ok(Redirect::temporary(&format!(
                "{}/auth/callback?error={}",
                frontend_url,
                urlencoding::encode(safe_error)
            )));
        }
    };

    let state = params.get("state").map(|s| s.to_string());

    // S1: read the browser-session binding cookie set at login time. The
    // callback consume path requires it to match the hash stored alongside
    // the `state` row (login-CSRF defense). Legacy state rows with a NULL
    // binding hash skip the check, so an in-flight login started before this
    // change still completes. Clear the cookie regardless — it's single-use.
    let session_binding = cookies
        .get(talos_api::schema::auth::OAUTH_SESSION_BINDING_COOKIE)
        .map(|c| c.value().to_string());
    if session_binding.is_some() {
        talos_api::schema::auth::clear_oauth_session_binding_cookie(&cookies);
    }

    // Handle OAuth callback with CSRF validation
    let user_info = match oauth_service
        .handle_callback(
            provider_enum.clone(),
            code.to_string(),
            state,
            session_binding.as_deref(),
        )
        .await
    {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("❌ OAuth callback error: {}", e);
            oauth_service
                .log_oauth_event(
                    None,
                    &provider_enum,
                    "login_failed",
                    false,
                    Some(&e.to_string()),
                )
                .await
                .ok();
            return Ok(Redirect::temporary(&format!(
                "{}/auth/callback?error={}",
                frontend_url,
                urlencoding::encode("csrf_mismatch")
            )));
        }
    };

    // Store user_info for potential Google Calendar integration
    let user_info_clone = user_info.clone();

    // Link or create user
    let (user_id, is_new_user) = oauth_service
        .link_or_create_user(provider_enum.clone(), user_info, None)
        .await
        .map_err(|_e| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    // RFC 0004: give brand-new OAuth users a personal organization (their
    // org-as-tenant home), mirroring the GraphQL signup path. Best-effort
    // + idempotent — `create_personal_org` repairs a miss, and existing
    // users already have one via the M1 backfill, so this never blocks
    // login.
    if is_new_user {
        if let Err(e) = talos_organizations::OrganizationService::create_personal_org(
            &google_calendar_service.db_pool,
            user_id,
            user_info_clone.name.as_deref(),
        )
        .await
        {
            tracing::error!(user_id = %user_id, "Failed to create personal org for new OAuth user (will be repaired): {e}");
        }

        // Phase D2.3: provision the default actor for brand-new OAuth users
        // too (same rationale as the GraphQL signup path — the fallback
        // principal the trg_set_default_actor trigger stamps onto actor-less
        // execution inserts). Best-effort + idempotent; created after the
        // personal org so the org-scoped write has its org.
        let actor_repo =
            talos_actor_repository::ActorRepository::new(google_calendar_service.db_pool.clone());
        if let Err(e) = actor_repo.get_or_create_default_actor(user_id).await {
            tracing::error!(user_id = %user_id, "Failed to create default actor for new OAuth user (will be repaired): {e}");
        }
    }

    // Check if this is a Google OAuth callback with Calendar scopes
    if provider_enum == OAuthProvider::Google {
        let is_calendar_integration = user_info_clone
            .scope
            .as_deref()
            .map(|s| s.contains("calendar"))
            .unwrap_or(false)
            || user_info_clone.refresh_token.is_some();

        if is_calendar_integration {
            // Get or create OAuth account
            let oauth_account = sqlx::query_as::<_, (uuid::Uuid,)>(
                "SELECT id FROM oauth_accounts
                 WHERE user_id = $1 AND provider = 'google'
                 ORDER BY created_at DESC
                 LIMIT 1",
            )
            .bind(user_id)
            .fetch_optional(&google_calendar_service.db_pool)
            .await
            .ok()
            .flatten();

            if let Some((oauth_account_id,)) = oauth_account {
                // Create Google Calendar integration
                let scope_str = user_info_clone.scope.clone().unwrap_or_else(|| "https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/calendar.events.readonly".to_string());

                if let (Some(access_token), Some(refresh_token), Some(expires_in)) = (
                    &user_info_clone.access_token,
                    &user_info_clone.refresh_token,
                    user_info_clone.expires_in,
                ) {
                    // MCP-801 (2026-05-14): surface integration-creation
                    // failures truthfully. Pre-fix `let _ = ...await`
                    // discarded the Result and the subsequent ✅ INFO log
                    // fired UNCONDITIONALLY — operators trying to debug a
                    // user's "calendar isn't working" report saw "✅
                    // Created" in the logs and concluded the integration
                    // existed, then chased ghosts elsewhere. Most-likely
                    // failure modes are transient (DB hiccup mid-OAuth-
                    // callback, NATS publish race, integration_state RPC
                    // delivery error); user retries by reconnecting Google
                    // Calendar in the settings UI. Capturing Err here lets
                    // the operator's first log query find the actual
                    // failure cause instead of silently-misleading success.
                    // Same misleading-success class as MCP-737/738/800.
                    // OAuth callback flow continues regardless — the login
                    // itself succeeded; only the calendar bolt-on failed.
                    match google_calendar_service
                        .create_or_update_integration(
                            user_id,
                            oauth_account_id,
                            access_token.clone(),
                            refresh_token.clone(),
                            expires_in,
                            scope_str,
                        )
                        .await
                    {
                        Ok(_) => {
                            tracing::info!(
                                "✅ Created Google Calendar integration for user {}",
                                user_id
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                target: "talos_audit",
                                user_id = %user_id,
                                oauth_account_id = %oauth_account_id,
                                error = ?e,
                                "Google Calendar integration creation failed during OAuth callback — \
                                 user can retry by reconnecting in settings; underlying error logged"
                            );
                        }
                    }
                } else {
                    tracing::warn!("⚠️ Failed to create Google Calendar integration for user {} because refresh_token or access_token is missing (likely user did not grant offline access on first prompt).", user_id);
                }
            }
        }
    }

    // Log successful OAuth login
    oauth_service
        .log_oauth_event(
            Some(user_id),
            &provider_enum,
            if is_new_user {
                "signup_oauth"
            } else {
                "login_oauth"
            },
            true,
            None,
        )
        .await
        .ok();

    // Get user details
    let user = auth_service
        .get_user(user_id)
        .await
        .map_err(|_e| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    // Generate tokens.
    //
    // SECURITY: if the user has TOTP enabled, mint a PRE-2FA token (the same
    // shape `auth_service.login()` returns for password+TOTP users). The
    // frontend then redirects to the TOTP entry page; verify_two_factor
    // upgrades to a fully-verified session. Hardcoding `true` here would
    // bypass 2FA for anyone who can complete an OAuth handshake with the
    // upstream provider — i.e. Google-account compromise = Talos session,
    // even when the user thinks TOTP is protecting them.
    let is_2fa_verified = !user.totp_enabled.unwrap_or(false);
    let access_token = auth_service
        .generate_access_token(&user, is_2fa_verified)
        .map_err(|_e| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let refresh_token = auth_service
        .generate_refresh_token(user_id, is_2fa_verified)
        .await
        .map_err(|_e| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    // Set httpOnly cookies.
    // MCP-1040 (2026-05-15): canonical session-cookie installer.
    // MCP-763 originally fixed a `set_secure(true)` vs `is_production`
    // gating drift between this OAuth callback and the login mutation;
    // MCP-1040 collapses both call paths into the single
    // `talos_api::schema::auth::set_session_cookies` helper so future
    // policy changes (TTL, SameSite, Partitioned, Domain) can't drift
    // back into asymmetry.
    talos_api::schema::auth::set_session_cookies(&cookies, &access_token, &refresh_token);

    // Redirect to frontend with success indicator
    Ok(Redirect::temporary(&format!(
        "{}/auth/callback?success=true",
        frontend_url
    )))
}
// build test 1773350690

mod secrets_rotation;
mod tenancy;

#[cfg(test)]
mod worker_registration_auth_tests {
    use super::{
        check_registration_freshness, classify_registration_bearer, provisioning_token_hash,
        RegBearerPath, WORKER_REG_FUTURE_MS, WORKER_REG_PAST_MS,
    };
    use axum::http::StatusCode;

    const NOW: u64 = 1_700_000_000_000;
    const TOKEN: &str = "s3cret-registration-token";

    #[test]
    fn accepts_fresh_timestamps() {
        assert!(check_registration_freshness(NOW, NOW).is_ok());
        // Within the past window and the future window.
        assert!(check_registration_freshness(NOW - WORKER_REG_PAST_MS + 1, NOW).is_ok());
        assert!(check_registration_freshness(NOW + WORKER_REG_FUTURE_MS, NOW).is_ok());
    }

    #[test]
    fn rejects_stale_and_future_dated() {
        // One ms past the past window.
        assert_eq!(
            check_registration_freshness(NOW - WORKER_REG_PAST_MS - 1, NOW)
                .unwrap_err()
                .0,
            StatusCode::BAD_REQUEST
        );
        // One ms past the future window.
        assert_eq!(
            check_registration_freshness(NOW + WORKER_REG_FUTURE_MS + 1, NOW)
                .unwrap_err()
                .0,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn shared_token_classification_respects_enforcement_flag() {
        // Exact shared-token match, enforcement off → legacy TOFU path.
        assert_eq!(
            classify_registration_bearer(TOKEN, Some(TOKEN), false),
            RegBearerPath::LegacyShared
        );
        // Same match under enforcement → refused-by-policy (handler logs, 401).
        assert_eq!(
            classify_registration_bearer(TOKEN, Some(TOKEN), true),
            RegBearerPath::SharedRefusedByPolicy
        );
    }

    #[test]
    fn non_shared_bearers_route_to_the_provisioning_path() {
        // Same length, different content (the ct_eq branch).
        let wrong = "S3cret-registration-token";
        assert_eq!(wrong.len(), TOKEN.len());
        assert_eq!(
            classify_registration_bearer(wrong, Some(TOKEN), false),
            RegBearerPath::Provisioning
        );
        // Different length (the length guard before ct_eq).
        assert_eq!(
            classify_registration_bearer("short", Some(TOKEN), false),
            RegBearerPath::Provisioning
        );
        // Bound-token-only deployment: no shared token configured at all.
        assert_eq!(
            classify_registration_bearer(TOKEN, None, true),
            RegBearerPath::Provisioning
        );
    }

    #[test]
    fn token_hash_is_sha256_hex_of_the_raw_bearer() {
        // Pinned vector so the CLI mint and the endpoint redeem can never
        // drift: sha256("wpt_test") — independently verifiable.
        assert_eq!(
            provisioning_token_hash("wpt_test"),
            "137e7e89843ad7a07606e9cf6fc91eb2e95f9be2612a320c3945dd2e22227da0"
        );
    }
}

#[cfg(test)]
mod scrub_wasm_log_for_broadcast_tests {
    use super::{scrub_wasm_log_for_broadcast, MAX_BROADCAST_LOG_CHARS};

    #[test]
    fn redacts_anthropic_secret() {
        // MCP-1011 sibling: a WASM module emitting `sk-ant-...` must
        // have it redacted BEFORE the broadcast lands on the live
        // `execution_updates` channel. The persistence path
        // (`add_workflow_log`) applied this; the broadcast didn't.
        let raw = "thinking response sk-ant-abcdefghijklmnopqrstuvwxyz0123456789 returned";
        let out = scrub_wasm_log_for_broadcast(raw);
        assert!(
            !out.contains("sk-ant-abcdefghijklmnopqrstuvwxyz0123456789"),
            "DLP scrubber must remove the secret. Got: {out}"
        );
    }

    #[test]
    fn redacts_bearer_token() {
        let raw = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig";
        let out = scrub_wasm_log_for_broadcast(raw);
        assert!(
            !out.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"),
            "Bearer JWT must be redacted. Got: {out}"
        );
    }

    #[test]
    fn redacts_github_token() {
        let raw = "git push uses ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // secret-scan-allow: DLP redaction test fixture
        let out = scrub_wasm_log_for_broadcast(raw);
        assert!(
            !out.contains("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), // secret-scan-allow: DLP redaction test fixture
            "GitHub PAT must be redacted. Got: {out}"
        );
    }

    #[test]
    fn strips_control_chars_except_whitespace() {
        // ANSI escape sequences and other control chars must not
        // reach operator dashboards (terminal-render attacks). \n,
        // \t, \r preserved so multi-line logs format correctly.
        let raw = "before\x1b[31mafter\nnext\ttabbed\rret\x07bell";
        let out = scrub_wasm_log_for_broadcast(raw);
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\x07'));
        assert!(out.contains('\n'));
        assert!(out.contains('\t'));
        assert!(out.contains('\r'));
    }

    #[test]
    fn truncates_oversize_input() {
        // Char-based truncation must respect the 8 KiB cap so the
        // broadcast can't carry more than `add_workflow_log` persists.
        let raw: String = "a".repeat(MAX_BROADCAST_LOG_CHARS + 1000);
        let out = scrub_wasm_log_for_broadcast(&raw);
        assert!(out.contains("... (truncated)"));
        // After truncation the prefix is exactly MAX chars, then the
        // marker; total chars <= cap + marker length.
        assert!(out.chars().count() <= MAX_BROADCAST_LOG_CHARS + "... (truncated)".chars().count());
    }

    #[test]
    fn small_input_passes_through_clean() {
        let raw = "user logged in successfully";
        let out = scrub_wasm_log_for_broadcast(raw);
        assert_eq!(out, raw);
    }
}
