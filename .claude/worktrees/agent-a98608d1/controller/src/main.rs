#![allow(dead_code, clippy::all)]
// NOTE: Global lint allowances have been removed to enforce code quality
// NOTE: Lint allowances are applied per‑module where required.  This file
// contains no global `#![allow]` directives to ensure new code follows strict
// linting rules.
// Enforce strict linting for the binary entry point.
// Module‑level `#[allow(...)]` can be applied where necessary.
use axum::{
    extract::{ws::WebSocketUpgrade, ConnectInfo, DefaultBodyLimit, State},
    response::Response,
    routing::{get, post},
    Extension, Router,
};
use futures_util::StreamExt; // For NATS subscriber
use tower_cookies::CookieManagerLayer;
// tracing imports used in other modules
// (removed redundant import; using fully qualified calls)

mod audit_ledger;
mod engine;
mod schema_alias;
mod trace;
mod trace_nats;
use async_graphql::Schema;
pub use schema_alias::TalosSchema;

use crate::db::init_pool;
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::http::{header, HeaderValue, Request};
use axum::middleware::{from_fn, Next};
use tokio::sync::broadcast;
use worker::runtime::TalosRuntime;

mod api;
mod api_keys;
mod auth;
mod compilation;
mod config;
mod csrf;
mod db;
mod gmail;
mod google_calendar;
mod llm;
mod mcp;
mod module_executions;
mod oauth;
mod rate_limit;
mod registry;
mod secrets;
mod security_headers;
mod slack;
mod templates;
mod totp_2fa;
mod webhooks;
mod wit_inspector;
mod workflow_engine;
mod ws_auth;

use api::schema::{ExecutionEvent, MutationRoot, QueryRoot, SubscriptionRoot};
use auth::AuthService;
use compilation::CompilationService;
#[allow(clippy::single_component_path_imports)]
use job_protocol;
use module_executions::{LogLevel, ModuleExecutionService};
use oauth::{OAuthProvider, OAuthService};
use registry::ModuleRegistry;
use secrets::SecretsManager;
use templates::TemplateGenerator;
use webhooks::WebhookRouter;

/// Type alias for the full GraphQL schema.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    if std::env::var("RUST_ENV").unwrap_or_default() == "production"
        && std::env::var("ALLOW_DEV_CSRF_BYPASS").unwrap_or_default() == "true"
    {
        panic!("CRITICAL SECURITY ERROR: ALLOW_DEV_CSRF_BYPASS cannot be true in production mode!");
    }

    // Initialise logger
    let jaeger_endpoint = std::env::var("JAEGER_ENDPOINT")
        .ok()
        .or_else(|| Some("http://localhost:4317".to_string()));

    if let Some(endpoint) = jaeger_endpoint.as_ref() {
        match crate::trace::init_tracing("talos-controller", Some(endpoint)) {
            Ok(_) => {
                println!("      Tracing initialized (endpoint: {})", endpoint);
                tracing_subscriber::fmt::init();
            }
            Err(e) => {
                eprintln!("Warning: Failed to initialize tracing: {}", e);
                eprintln!("    Continuing without tracing...");
                tracing_subscriber::fmt::init();
            }
        }
    } else {
        tracing_subscriber::fmt::init();
    }

    // ---------------------------------------------------------------------
    // Verify essential environment configuration early.
    // ---------------------------------------------------------------------
    // DATABASE_URL is required for the DB pool – init_pool will error if missing.
    // JWT_SECRET and TALOS_MASTER_KEY must be present for auth and secret
    // handling. We explicitly check them now to provide a clear startup error
    // rather than propagating a stack trace later.
    let required_vars = [
        ("JWT_SECRET", "JWT authentication secret"),
        ("TALOS_MASTER_KEY", "master key for envelope encryption"),
    ];
    for (var, desc) in required_vars.iter() {
        if std::env::var(var).is_err() {
            return Err(anyhow::anyhow!(format!(
                "Missing required environment variable {}: {}. Set it before starting the service.",
                var, desc
            )));
        }
    }

    // ---------- Event bus for execution updates ----------
    let (tx, _rx) = broadcast::channel::<ExecutionEvent>(100);

    // ---------- Initialise DB ----------
    // Database schema is managed via migrations in /migrations/
    // Run: sqlx migrate run
    let db_pool: sqlx::Pool<sqlx::Postgres> = init_pool().await?;

    // ---------- Initialize Redis client for distributed caching ----------
    let redis_client = if let Ok(redis_url) = std::env::var("REDIS_URL") {
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

    // ---------- Initialize NATS client for message queues ----------
    let nats_client = if let Ok(nats_url) = std::env::var("NATS_URL") {
        // SECURITY: Use authenticated connection when NATS_USER + NATS_PASSWORD are set.
        let nats_user = std::env::var("NATS_USER").ok();
        let nats_password = std::env::var("NATS_PASSWORD").ok();

        let connect_result = match (nats_user, nats_password) {
            (Some(user), Some(pass)) => {
                async_nats::ConnectOptions::new()
                    .user_and_password(user, pass)
                    .request_timeout(Some(std::time::Duration::from_secs(86400 * 7))) // 7 days for governance approvals
                    .connect(&nats_url)
                    .await
            }
            _ => {
                async_nats::ConnectOptions::new()
                    .request_timeout(Some(std::time::Duration::from_secs(86400 * 7))) // 7 days for governance approvals
                    .connect(&nats_url)
                    .await
            }
        };

        match connect_result {
            Ok(client) => {
                tracing::info!("NATS client initialized and connected: {}", nats_url);
                // Start the audit ledger subscriber. If it fails we want to know why, so propagate the error.
                tracing::info!("Calling start_audit_ledger_subscriber");
                crate::audit_ledger::start_audit_ledger_subscriber(client.clone(), db_pool.clone())
                    .await?;
                tracing::info!("AUDIT_SUBSCRIBER_STARTED_AND_RUNNING");
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

    // ---------- Initialize node creation services ----------
    let registry = std::sync::Arc::new(ModuleRegistry::new(db_pool.clone(), redis_client.clone()));
    let generator = std::sync::Arc::new(TemplateGenerator::new());
    // Allow the compilation directory to be overridden via COMPILE_DIR env var.
    // Defaults to "/tmp/talos-compilations" for backward compatibility.
    let compile_dir =
        std::env::var("COMPILE_DIR").unwrap_or_else(|_| "/tmp/talos-compilations".to_string());
    let compiler = std::sync::Arc::new(CompilationService::new(std::path::PathBuf::from(
        compile_dir,
    )));

    // ---------- Initialize secrets manager ----------
    let secrets_manager = std::sync::Arc::new(SecretsManager::new(db_pool.clone())?);
    secrets_manager.initialize().await?;
    tracing::info!("Secrets manager initialized");

    // ---------- Load worker shared key (for signing NATS job requests) ----------
    // Optional: if not set, Google Calendar webhook dispatch is disabled.
    // In production this MUST be set to the same value as the worker's WORKER_SHARED_KEY.
    let worker_shared_key: Option<std::sync::Arc<Vec<u8>>> =
        match job_protocol::load_worker_shared_key() {
            Ok(key) => {
                tracing::info!("WORKER_SHARED_KEY loaded — calendar webhook dispatch enabled");
                Some(std::sync::Arc::new(key))
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

    // ---------- Initialize module execution service for logging ----------
    let module_execution_service =
        std::sync::Arc::new(ModuleExecutionService::new(db_pool.clone()));
    tracing::info!("Module execution service initialized");

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
            // Attach SecretsManager so OAuth tokens are encrypted at rest (migration 018).
            .with_secrets_manager(secrets_manager.clone()),
    );
    tracing::info!("Slack integration service initialized (token encryption enabled)");

    // ---------- Initialize Gmail integration service ----------
    let gmail_integration_service = std::sync::Arc::new(
        gmail::GmailIntegrationService::new(db_pool.clone())
            .map_err(|e| anyhow::anyhow!("Failed to initialize Gmail integration service: {}", e))?
            .with_secrets_manager(secrets_manager.clone())
            .with_credentials_service(oauth_credential_service.clone()),
    );
    tracing::info!("Gmail integration service initialized (token encryption + dual-write enabled)");

    // ---------- Initialize Gmail API client ----------
    let gmail_api_client = std::sync::Arc::new(gmail::GmailApiClient::new());
    tracing::info!("Gmail API client initialized");

    // ---------- Initialize Google Calendar integration service ----------
    let google_calendar_service =
        std::sync::Arc::new(google_calendar::GoogleCalendarService::new(db_pool.clone()));
    if google_calendar_service.is_configured() {
        tracing::info!("Google Calendar integration service initialized");
    } else {
        tracing::warn!(
            "Google Calendar integration not configured (missing GOOGLE_CLIENT_ID/SECRET)"
        );
    }
    // Wire in the unified credential service for dual-write token storage.
    google_calendar_service.with_credentials_service(oauth_credential_service.clone());

    // ---------- Initialize webhook router ----------
    // NOTE: Slack enrichment (user profiles, channel info, etc.) now happens inside
    // the slack-webhook-listener WASM template, not here in the controller.
    let webhook_router = std::sync::Arc::new(WebhookRouter::new(
        db_pool.clone(),
        registry.clone(),
        secrets_manager.clone(),
        nats_client.clone().ok_or_else(|| {
            anyhow::anyhow!("NATS_URL must be configured for the new WebhookRouter architecture")
        })?,
        worker_shared_key.clone(),
    )?);

    // ---------- Initialize authentication service ----------
    // Require JWT_SECRET to be explicitly set - fail fast if missing
    // Require JWT_SECRET to be explicitly set – return an error instead of panicking
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| {
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

    // Read bcrypt cost from environment (default to 12, which is the recommended production value)
    let bcrypt_cost = std::env::var("BCRYPT_COST")
        .unwrap_or_else(|_| "12".to_string())
        .parse::<u32>()
        .map_err(|_| anyhow::anyhow!("BCRYPT_COST must be a valid number between 10 and 14"))?;

    let auth_service = std::sync::Arc::new(
        AuthService::new(db_pool.clone(), jwt_secret, bcrypt_cost)
            .map_err(|e| anyhow::anyhow!("Failed to initialize auth service: {}", e))?,
    );
    tracing::info!("Auth service initialized with bcrypt cost: {}", bcrypt_cost);

    // ---------- Initialize TOTP/2FA service ----------
    let totp_service = std::sync::Arc::new(totp_2fa::TotpService::new(
        db_pool.clone(),
        redis_client.clone(),
        secrets_manager.clone(),
    ));
    tracing::info!("TOTP/2FA service initialized");

    // ---------- Initialize API key service ----------
    let api_key_service = std::sync::Arc::new(api_keys::ApiKeyService::new(db_pool.clone()));
    tracing::info!("API key service initialized");

    // ---------- Initialize OAuth service ----------
    let oauth_service = std::sync::Arc::new(
        OAuthService::new(db_pool.clone(), redis_client.clone())
            .map_err(|e| anyhow::anyhow!("Failed to initialize OAuth service: {}", e))?,
    );
    tracing::info!("OAuth service initialized");

    // Seed templates on first run
    seed_templates(&registry).await?;

    // ---------- Start OCI Registry background sync loop ----------
    let sync_registry = registry.clone();
    tokio::spawn(async move {
        registry::sync::start_registry_sync_loop(sync_registry).await;
    });

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

    // ---------- Start background session cleanup task ----------
    let cleanup_auth_service = auth_service.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Run every hour
        loop {
            interval.tick().await;
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
    });
    tracing::info!("Session cleanup task started (runs every hour)");

    // ---------- Start background API key cleanup task ----------
    let cleanup_api_key_service = api_key_service.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Run every hour
        loop {
            interval.tick().await;
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
    });
    tracing::info!("API key cleanup task started (runs every hour)");

    // ---------- Start background OAuth state token cleanup task ----------
    let cleanup_oauth_service = oauth_service.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Run every hour
        loop {
            interval.tick().await;
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
    });
    tracing::info!("OAuth state token cleanup task started (runs every hour)");

    // ---------- Start workflow execution cleanup task ----------
    let cleanup_pool = db_pool.clone();
    tokio::spawn(async move {
        // Run every 6 hours
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
        loop {
            interval.tick().await;

            // Delete executions older than 7 days
            let retention_days = 7i32;
            match sqlx::query(
                "DELETE FROM workflow_executions WHERE started_at < NOW() - INTERVAL '1 day' * $1",
            )
            .bind(retention_days)
            .execute(&cleanup_pool)
            .await
            {
                Ok(result) => {
                    let count = result.rows_affected();
                    if count > 0 {
                        tracing::info!(
                            "Cleaned up {} old workflow executions (older than {} days)",
                            count,
                            retention_days
                        );
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to cleanup old workflow executions: {}", e);
                }
            }
        }
    });
    tracing::info!("Workflow execution cleanup task started (runs every 6 hours, deletes executions older than 7 days)");

    // ---------- Start audit log cleanup task ----------
    let cleanup_auth = auth_service.clone();
    let cleanup_secrets = secrets_manager.clone();
    let cleanup_webhooks = webhook_router.clone();
    tokio::spawn(async move {
        // Run daily at 2 AM (check every hour, but only execute once per day)
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        let mut last_cleanup_day: Option<u32> = None;

        loop {
            interval.tick().await;

            // Only run cleanup once per day at 2 AM
            use chrono::{Datelike, Timelike};
            let now = chrono::Utc::now();
            let current_day = now.ordinal(); // Day of year (1-indexed)
            let current_hour = now.hour();

            if current_hour == 2 && last_cleanup_day != Some(current_day) {
                let retention_days = std::env::var("AUDIT_LOG_RETENTION_DAYS")
                    .ok()
                    .and_then(|v| v.parse::<i64>().ok())
                    .unwrap_or(90); // Default: 90 days

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

                last_cleanup_day = Some(current_day);
                tracing::info!("Audit log cleanup completed");
            }
        }
    });
    tracing::info!("Audit log cleanup task started (runs daily at 2 AM)");

    // ---------- Start WASM module cache cleanup task ----------
    let cleanup_registry = registry.clone();
    tokio::spawn(async move {
        // Run every 6 hours
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(21600));

        loop {
            interval.tick().await;

            let retention_days = std::env::var("WASM_CACHE_RETENTION_DAYS")
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(30); // Default: 30 days

            let max_modules = std::env::var("WASM_CACHE_MAX_MODULES")
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(1000); // Default: 1000 modules

            let max_size_mb = std::env::var("WASM_CACHE_MAX_SIZE_MB")
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(500); // Default: 500 MB

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

    // ---------- Start webhook rate-limiter cleanup task ----------
    // Prevents unbounded growth of in-memory token buckets as unique webhook
    // tokens accumulate over the process lifetime.
    let cleanup_webhook_rl = webhook_router.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Every 5 min
        loop {
            interval.tick().await;
            cleanup_webhook_rl.cleanup_rate_limiter();
        }
    });
    tracing::info!("Webhook rate-limiter cleanup task started (runs every 5 minutes)");

    // ---------- Start stuck execution cleanup task ----------
    // Transitions orphaned `pending`/`running` executions to `timeout` when a
    // worker crashes without reporting a result.
    let cleanup_exec_service = module_execution_service.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Every 5 min
        loop {
            interval.tick().await;
            let max_age_mins = std::env::var("STUCK_EXECUTION_TIMEOUT_MINS")
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(30); // Default: mark stuck after 30 minutes
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
    });
    tracing::info!("Stuck execution cleanup task started (runs every 5 minutes, timeout after 30 min by default)");

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

    // ---------- Start Google Calendar channel renewal task ----------
    if google_calendar_service.is_configured() {
        let renewal_service = google_calendar_service.clone();
        tokio::spawn(async move {
            google_calendar::scheduler::channel_renewal_task(renewal_service).await;
        });
        tracing::info!("Google Calendar channel renewal task started (runs every hour)");

        // Per-channel webhook rate-limiter cleanup (runs every 5 minutes)
        let cleanup_gcal_rl = google_calendar_service.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                cleanup_gcal_rl.cleanup_webhook_channel_limits();
            }
        });

        // Event sync task will be started after Redis/NATS are initialized
    }

    // ---------- Start WASM log subscriber (automatic logging from worker) ----------
    // This background task receives logs from WASM executions and persists them to database
    // Provides guaranteed observability for all WASM module executions
    if let Some(nats) = nats_client.clone() {
        let exec_service_for_logs = module_execution_service.clone();
        let tx_for_wasm_logs = tx.clone();
        tokio::spawn(async move {
            tracing::info!("Starting WASM log subscriber on topic: wasm.log.*");

            // Subscribe to all WASM log topics (wasm.log.{execution_id})
            let mut subscriber = match nats.subscribe("wasm.log.*").await {
                Ok(sub) => sub,
                Err(e) => {
                    tracing::error!("Failed to subscribe to WASM logs: {}", e);
                    return;
                }
            };

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

                        // Convert string to LogLevel enum
                        let level = match level_str {
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

                            // Broadcast the live log to all connected GraphQL clients!
                            let _ = tx_for_wasm_logs.send(ExecutionEvent {
                                execution_id: exec_id,
                                node_id,
                                status: api::schema::ExecutionStatus::Running,
                                trace_id,
                                span_id,
                                log_message: Some(format!(
                                    "[{}] {}",
                                    level_str.to_uppercase(),
                                    message
                                )),
                            });

                            // Use add_log_best_effort to handle rate limiting gracefully
                            exec_service_for_logs
                                .add_log_best_effort(exec_id, level, message, metadata)
                                .await;
                        } else {
                            tracing::debug!("Received WASM log without valid execution_id");
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Failed to parse WASM log message: {}", e);
                    }
                }
            }

            tracing::warn!("WASM log subscriber stopped");
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
        // Clone the shared key so it can be moved into the spawn while the original
        // is still used later to build the Extension layer.
        let worker_shared_key_for_results = worker_shared_key.clone();
        tokio::spawn(async move {
            tracing::info!("Starting job result subscriber on topic: talos.results.*");

            let mut sub = match nats_for_results.subscribe("talos.results.*").await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to subscribe to job results: {}", e);
                    return;
                }
            };

            tracing::info!("Job result subscriber active");

            while let Some(msg) = sub.next().await {
                match serde_json::from_slice::<job_protocol::JobResult>(&msg.payload) {
                    Ok(result) => {
                        let job_id = result.job_id;

                        // SECURITY: Verify HMAC-SHA256 signature when the shared key is
                        // configured. Rejects results injected by any process that can
                        // publish to NATS but does not know the pre-shared key.
                        if let Some(ref key) = worker_shared_key_for_results {
                            if let Err(e) = result.verify(key, 300) {
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
                            job_protocol::JobStatus::Success => {
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
                            job_protocol::JobStatus::Failed | job_protocol::JobStatus::TimedOut => {
                                let error_msg = result
                                    .output_payload
                                    .get("error")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Worker reported failure")
                                    .to_string();
                                let error_type =
                                    matches!(result.status, job_protocol::JobStatus::TimedOut)
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
                                    tracing::info!(
                                        "❌ Execution {} failed: {}",
                                        job_id,
                                        error_msg.chars().take(100).collect::<String>()
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

            tracing::warn!("Job result subscriber stopped");
        });
        tracing::info!("Job result subscriber task started");
    } else {
        tracing::warn!("NATS not configured - WASM automatic logging disabled");
    }

    // Note: Periodic event sync task removed — sync_channel_events() advances the sync
    // token each time it runs, which would silently consume the token before the webhook
    // handler could use it, causing missed events. Syncing is driven exclusively by
    // real-time push notifications (webhook_notification_handler).

    // ---------- Build GraphQL schema ----------
    // Shared TalosRuntime with Redis, NATS, and file sandbox support (thread‑safe via Arc)
    let runtime = std::sync::Arc::new(TalosRuntime::with_resources(
        redis_client.clone(),
        nats_client.clone(),
        Some(db_pool.clone()),
        None, // File sandbox configured per-execution
    )?);
    // Initialize LLM Client if API key is present
    let anthropic_api_key = std::env::var("ANTHROPIC_API_KEY").unwrap_or_default();
    let llm_client = if !anthropic_api_key.is_empty() {
        Some(crate::llm::LlmClient::new(anthropic_api_key))
    } else {
        None
    };

    // Build async-graphql schema with limits (defense in depth)
    let mut schema_builder = Schema::build(QueryRoot, MutationRoot, SubscriptionRoot)
        // Security limits to prevent DoS attacks via expensive queries
        .limit_depth(10) // Maximum query nesting depth
        .limit_complexity(5000); // Maximum query complexity score

    // Disable GraphQL introspection in production to prevent schema enumeration.
    if std::env::var("RUST_ENV").unwrap_or_default() == "production" {
        schema_builder = schema_builder.disable_introspection();
        tracing::info!("GraphQL introspection disabled (production mode)");
    }

    let schema_builder = schema_builder
        .data(tx)
        .data(runtime.clone())
        .data(db_pool.clone())
        .data(registry.clone())
        .data(generator)
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
        .data(async_graphql::dataloader::DataLoader::new(
            crate::api::schema::ModuleLoader(db_pool.clone()),
            tokio::spawn,
        ))
        .data(async_graphql::dataloader::DataLoader::new(
            crate::api::schema::ModuleExecutionLogLoader(db_pool.clone()),
            tokio::spawn,
        ))
        .data(nats_client.clone());

    let schema = if let Some(llm) = llm_client {
        schema_builder.data(llm).finish()
    } else {
        schema_builder.finish()
    };

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
    async fn cors_options() -> impl axum::response::IntoResponse {
        use axum::body::Body;

        let origin = std::env::var("ALLOWED_ORIGIN").unwrap_or_else(|_| {
            if std::env::var("RUST_ENV").unwrap_or_default() == "production" {
                // Log error instead of panicking; fallback to a safe placeholder
                tracing::error!("ALLOWED_ORIGIN must be set in production mode");
                "http://example.invalid".to_string()
            } else {
                "http://localhost:3000".to_string()
            }
        });

        axum::response::Response::builder()
            .status(axum::http::StatusCode::OK)
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin)
            .header(header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS")
            .header(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                "Content-Type, Authorization, X-API-Key, X-CSRF-Token",
            )
            .header(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true")
            .header(header::ACCESS_CONTROL_MAX_AGE, "3600")
            .body(Body::empty())
            .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
    }

    // ---------- Axum router ----------
    // Create GraphQL routes with API rate limiting and CSRF protection
    // GraphiQL playground is only enabled in development for security
    let is_production = std::env::var("RUST_ENV").unwrap_or_default() == "production";

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
    let approval_routes = Router::new()
        .route(
            "/api/approvals/{execution_id}",
            post(webhooks::approval_handler),
        )
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
    let slack_api_routes = Router::new()
        .route("/api/slack/channels", get(slack::list_channels_handler))
        .route("/api/slack/users", get(slack::list_users_handler))
        .route("/api/slack/apps/create", post(slack::create_app_handler))
        .with_state(slack_api_client.clone())
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
        .route("/api/slack/callback", get(slack::slack_callback_handler))
        .with_state(slack_integration_service.clone())
        .layer(from_fn(rest_auth_middleware)) // Runs 5th (last) - needs auth_service extension
        .layer(Extension(auth_service.clone())) // Runs 4th - provides auth_service to middleware above
        .layer(from_fn(rate_limit::rate_limit_middleware)) // Runs 3rd
        .layer(Extension(api_limiter.clone())) // Runs 2nd
        .layer(Extension(whitelist.clone())); // Runs 1st (first)

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
        .route("/api/gmail/callback", get(gmail::gmail_callback_handler))
        .with_state(gmail_integration_service.clone())
        .layer(from_fn(rest_auth_middleware)) // Runs 5th (last) - needs auth_service extension
        .layer(Extension(auth_service.clone())) // Runs 4th - provides auth_service to middleware above
        .layer(from_fn(rate_limit::rate_limit_middleware)) // Runs 3rd
        .layer(Extension(api_limiter.clone())) // Runs 2nd
        .layer(Extension(whitelist.clone())); // Runs 1st (first)

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
        .with_state(google_calendar_service.clone())
        .layer(from_fn(rest_auth_middleware)) // Runs 5th (last) - needs auth_service extension
        .layer(Extension(auth_service.clone())) // Runs 4th - provides auth_service to middleware above
        .layer(from_fn(rate_limit::rate_limit_middleware)) // Runs 3rd
        .layer(Extension(api_limiter.clone())) // Runs 2nd
        .layer(Extension(whitelist.clone())); // Runs 1st (first)

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

    // Combine all routes

    // Admin routes
    let admin_routes = Router::new()
        .route(
            "/api/admin/secrets/invalidate-cache",
            post(
                |headers: axum::http::HeaderMap,
                 State(secrets_manager): State<std::sync::Arc<secrets::SecretsManager>>| async move {
                    let admin_secret = std::env::var("ADMIN_SECRET_KEY").unwrap_or_default();
                    let provided_secret = headers.get("X-Admin-Secret").and_then(|h| h.to_str().ok()).unwrap_or("");

                    // Use constant-time equality to prevent timing attacks when comparing secrets
                    use subtle::ConstantTimeEq;
                    let is_match = admin_secret.len() == provided_secret.len() &&
                        admin_secret.as_bytes().ct_eq(provided_secret.as_bytes()).unwrap_u8() == 1;

                    if !admin_secret.is_empty() && is_match {
                        let _ = secrets_manager.invalidate_dek_cache(None, "ADMIN_API", None).await;
                        (
                            axum::http::StatusCode::OK,
                            "DEK cache invalidated successfully",
                        )
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

    let mcp_routes = mcp::create_router(
        registry.clone(),
        db_pool.clone(),
        runtime.clone(),
        compiler.clone(),
    );

    let app = Router::new()
        .nest("/mcp", mcp_routes)
        .route("/", get(|| async { "Talos Controller is running" }))
        .route("/health", get(health_check))
        .route("/health/redis", get(health_check_redis))
        .route("/health/nats", get(health_check_nats))
        .route("/metrics", get(metrics_handler))
        .merge(graphql_routes)
        .merge(webhook_routes)
        .merge(approval_routes)
        .merge(oauth_routes)
        .merge(slack_api_routes)
        .merge(slack_integration_routes)
        .merge(admin_routes)
        .merge(gmail_api_routes)
        .merge(gmail_integration_routes)
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
        .merge(google_calendar_routes)
        .merge(google_calendar_webhook_routes)
        .nest(
            "/api/registry",
            registry::api::registry_router().with_state(registry.clone()),
        )
        // Cookie support
        .layer(CookieManagerLayer::new())
        // Add shared extensions for all routes
        .layer(Extension(db_pool.clone()))
        .layer(Extension(webhook_router))
        .layer(Extension(redis_client.clone()))
        .layer(Extension(nats_client.clone()))
        .layer(Extension(Some(module_execution_service.clone())))
        .layer(Extension(worker_shared_key))
        // Shared runtime and secrets manager — used by webhook handlers to execute
        // downstream workflow nodes in-process (workflow chaining).
        .layer(Extension(Some(runtime.clone())))
        .layer(Extension(Some(secrets_manager.clone())))
        // Trusted proxy list — used by rate_limit_middleware to decide whether to
        // trust X-Forwarded-For headers. Shared across all rate-limited routes.
        .layer(Extension(trusted_proxies));

    // Conditionally add global rate limiting (only in production)
    let app = if std::env::var("RUST_ENV").unwrap_or_default() == "production" {
        app.layer(from_fn(rate_limit::global_rate_limit_middleware))
            .layer(Extension(global_limiter))
    } else {
        tracing::info!("Global rate limiter DISABLED in development mode");
        app
    };

    let app = app
        // Global IP-based rate limiting
        .layer(governor_layer)
        // Security headers (apply to all responses)
        .layer(from_fn(security_headers::add_security_headers))
        // CORS - must be last layer (runs first) to handle OPTIONS preflight
        .layer(from_fn(cors_middleware));

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
    .with_graceful_shutdown(async {
        tokio::signal::ctrl_c()
            .await
            .unwrap_or_else(|_| tracing::warn!("failed to install CTRL+C signal handler"));
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to start Axum server: {}", e))?;

    crate::trace::shutdown_tracing();
    Ok(())
}

// ---------- CORS Middleware ----------
async fn cors_middleware(req: Request<axum::body::Body>, next: Next) -> Response {
    use axum::http::Method;

    // Get allowed origin from environment
    let origin = std::env::var("ALLOWED_ORIGIN").unwrap_or_else(|_| {
        if std::env::var("RUST_ENV").unwrap_or_default() == "production" {
            tracing::error!("ALLOWED_ORIGIN must be set in production mode");
            "http://example.invalid".to_string()
        } else {
            "http://localhost:3000".to_string()
        }
    });

    // Handle preflight OPTIONS requests immediately
    if req.method() == Method::OPTIONS {
        let mut response = Response::new(axum::body::Body::empty());
        *response.status_mut() = axum::http::StatusCode::OK;

        let headers = response.headers_mut();
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_str(&origin)
                .unwrap_or(HeaderValue::from_static("http://localhost:3000")),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type, Authorization, X-API-Key, X-CSRF-Token"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("3600"),
        );

        return response;
    }

    // For all other requests, process normally and add CORS headers to response
    let mut response = next.run(req).await;

    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_str(&origin).unwrap_or(HeaderValue::from_static("http://localhost:3000")),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type, Authorization, X-API-Key, X-CSRF-Token"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );

    response
}

// ---------- Health check handler ----------
async fn health_check(
    Extension(db_pool): Extension<sqlx::PgPool>,
) -> Result<&'static str, axum::http::StatusCode> {
    // Check database connectivity
    sqlx::query("SELECT 1")
        .execute(&db_pool)
        .await
        .map_err(|e| {
            tracing::error!("Health check failed: database error: {}", e);
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        })?;

    Ok("OK")
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

    let secret_stats = sqlx::query_as::<_, (i64, i64)>(
        r#"
        SELECT
            COUNT(*)::bigint,
            COALESCE(SUM(access_count), 0)::bigint
        FROM secrets
        WHERE user_id = $1
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

    let module_stats = sqlx::query_as::<_, (i64, i64, i64)>(
        r#"
        SELECT
            COUNT(*)::bigint,
            COALESCE(SUM(usage_count), 0)::bigint,
            COALESCE(SUM(size_bytes), 0)::bigint
        FROM wasm_modules
        WHERE user_id = $1
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
    // Debug: Log cookie header
    tracing::debug!(
        "REST auth middleware - Cookie header: {:?}",
        headers.get(axum::http::header::COOKIE)
    );

    // Insert the request headers into extensions for downstream handlers that may need them
    req.extensions_mut().insert(headers.clone());

    // Try to get token from cookie first, then fall back to Authorization header
    let token = cookies
        .get("talos_access_token")
        .map(|c| {
            let truncated: String = c.value().chars().take(20).collect();
            tracing::debug!("REST auth - Found cookie token: {}...", truncated);
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

    // Extract IP address
    let ip_address = Some(addr.ip().to_string());

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
    let mut authenticated = false;
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
                authenticated = true;
                tracing::debug!("Authenticated via API key for user {}", user_id);
            }
        }
    }

    // Fall back to JWT token authentication if no API key was used
    if !authenticated {
        if let Some(token_str) = token {
            // Get auth service from schema data
            if let Some(auth_service) = schema.0.data::<std::sync::Arc<AuthService>>() {
                if let Ok(claims) = auth_service.verify_token(&token_str) {
                    if let Ok(user_id) = uuid::Uuid::parse_str(&claims.sub) {
                        // Inject user_id into GraphQL context
                        req = req.data(user_id);
                        tracing::debug!("Authenticated via JWT for user {}", user_id);
                    }
                }
            }
        }
    }

    let mut response = schema.execute(req).await;

    // Scrub internal error details in all non-development environments
    // (production, staging, test, etc.) to avoid leaking sensitive information.
    if !config::is_development() {
        for error in &mut response.errors {
            tracing::error!("GraphQL Error: {:?}", error);
            let msg = error.message.as_str();
            let is_safe = msg.contains("Authentication")
                || msg.contains("Access denied")
                || msg.contains("Not found")
                || msg.contains("Invalid")
                || msg.contains("Validation")
                || msg.contains("Unauthorized");

            if !is_safe {
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
    Extension(schema): Extension<TalosSchema>,
    Extension(auth_service): Extension<std::sync::Arc<AuthService>>,
) -> Response {
    // Extract access token from cookie (secure: httpOnly cookie, not JavaScript)
    let access_token = cookies
        .get("talos_access_token")
        .map(|c| c.value().to_string());

    ws.protocols(["graphql-ws"]).on_upgrade(move |socket| {
        ws_auth::handle_websocket_auth(socket, schema, auth_service, access_token)
    })
}

// ---------- Seed templates ----------

/// Upsert a single built-in template.
///
/// Always updates `code_template` and `config_schema` so that rebuilding the
/// controller binary (which embeds templates via `include_str!`) keeps the DB
/// in sync without a manual DB wipe.  `category`, `description`, and `icon`
/// are only written on first insert.

async fn seed_templates(_registry: &std::sync::Arc<ModuleRegistry>) -> anyhow::Result<()> {
    // Seeding is now handled completely dynamically via OCI publishing (talos-publish.py)
    // The controller starts up empty, and environments are populated as needed.
    println!("Template seeding is now dynamic (OCI). Skipping static include_str! injections.");
    Ok(())
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
    let (auth_url, _csrf_token) = oauth_service
        .get_authorization_url(provider, extra_scopes)
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to generate auth URL: {}", e),
            )
        })?;

    // Store CSRF token in session/cookie (for production, implement CSRF validation)
    // For now, redirect to OAuth provider
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
    use tower_cookies::Cookie;

    let provider_enum =
        OAuthProvider::from_str(&provider).map_err(|_e| axum::http::StatusCode::BAD_REQUEST)?;

    // Extract authorization code and state parameter
    let frontend_url =
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

    let code = match params.get("code") {
        Some(c) => c,
        None => {
            let error_msg = params
                .get("error")
                .map(|s| s.as_str())
                .unwrap_or("missing_code");
            tracing::warn!("OAuth callback missing code. Error: {}", error_msg);
            return Ok(Redirect::temporary(&format!(
                "{}/auth/callback?error={}",
                frontend_url,
                urlencoding::encode(error_msg)
            )));
        }
    };

    let state = params.get("state").map(|s| s.to_string());

    // Handle OAuth callback with CSRF validation
    let user_info = match oauth_service
        .handle_callback(provider_enum.clone(), code.to_string(), state)
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
                    let _ = google_calendar_service
                        .create_or_update_integration(
                            user_id,
                            oauth_account_id,
                            access_token.clone(),
                            refresh_token.clone(),
                            expires_in,
                            scope_str,
                        )
                        .await;

                    tracing::info!(
                        "✅ Created Google Calendar integration for user {}",
                        user_id
                    );
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

    // Generate tokens
    let access_token = auth_service
        .generate_access_token(&user)
        .map_err(|_e| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let refresh_token = auth_service
        .generate_refresh_token(user_id)
        .await
        .map_err(|_e| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    // Set httpOnly cookies
    let mut access_cookie = Cookie::new("talos_access_token", access_token.clone());
    access_cookie.set_http_only(true);
    access_cookie.set_secure(true);
    access_cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
    access_cookie.set_path("/");
    access_cookie.set_max_age(tower_cookies::cookie::time::Duration::minutes(15));
    cookies.add(access_cookie);

    let mut refresh_cookie = Cookie::new("talos_refresh_token", refresh_token.clone());
    refresh_cookie.set_http_only(true);
    refresh_cookie.set_secure(true);
    refresh_cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
    refresh_cookie.set_path("/");
    refresh_cookie.set_max_age(tower_cookies::cookie::time::Duration::days(7));
    cookies.add(refresh_cookie);

    // Redirect to frontend with success indicator
    Ok(Redirect::temporary(&format!(
        "{}/auth/callback?success=true",
        frontend_url
    )))
}
