//! Service-construction phase functions for the controller binary's
//! `main()` — moved VERBATIM out of `controller/src/main.rs` in the 2026-07
//! decomposition. Startup ORDER is load-bearing and stays in `main()`; this
//! module only owns the construction bodies (DB / Redis / NATS init, the
//! core + platform service piles, crypto-hook registration, graph-RAG init,
//! the RPC HMAC ring + subscriber wiring, the GraphQL schema bundle, and
//! disk template / marketplace seeding). See main.rs for the phase structs
//! (`EventBuses`, `CoreServices`, `PlatformServices`, `RateLimiters`,
//! `SchemaBundle`) these functions produce and consume.
use crate::rpc_subscribers::{
    spawn_database_rpc_subscriber, spawn_graph_rpc_subscriber, spawn_integration_state_subscriber,
    spawn_integration_state_sweeper, spawn_memory_rpc_subscriber, spawn_ml_rpc_subscriber,
    spawn_state_write_subscriber,
};
use crate::*;

/// Postgres pool init + migrations + RLS-bypass warning + first-user
/// bootstrap + embedding warmup. Extracted verbatim from `main()`.
pub(crate) async fn init_database() -> anyhow::Result<sqlx::Pool<sqlx::Postgres>> {
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
pub(crate) async fn init_redis() -> Option<std::sync::Arc<redis::Client>> {
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
pub(crate) async fn init_nats() -> anyhow::Result<Option<std::sync::Arc<async_nats::Client>>> {
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
pub(crate) async fn build_core_services(
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
pub(crate) async fn register_crypto_hooks(
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
pub(crate) async fn build_platform_services(
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

/// Per-IP / global rate limiters + IP whitelist + trusted-proxy list.
/// Extracted verbatim from `main()`.
pub(crate) fn build_rate_limiters() -> RateLimiters {
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

/// Graph RAG service (Neo4j) init — TLS prod gate, vault-first key
/// resolution, and the tier-1 data-egress gate. Extracted verbatim from
/// `main()`.
pub(crate) async fn init_graph_rag(
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
pub(crate) async fn register_distributed_replay_guard(
    redis_client: Option<&std::sync::Arc<redis::Client>>,
) {
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
pub(crate) fn register_rpc_hmac_ring() -> anyhow::Result<bool> {
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
pub(crate) fn wire_rpc_subscribers(
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

/// Build the shared TalosRuntime, LLM client, repositories, cross-protocol
/// services, and the GraphQL schema. Extracted verbatim from `main()`. The
/// ExecutionOrchestrationService construction chains
/// `.with_event_sender(tx.clone())` — preserved exactly.
pub(crate) fn build_schema_and_services(
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
        // N+1 batchers for id-only child objects (schedule/approval/
        // execution → workflow name, workflow/execution → actor name,
        // workflow → latest execution). Keys carry the caller's user/org
        // scope so each batched query preserves the per-row tenancy
        // predicate — see the loader docs in talos-api/src/schema/types.rs.
        .data(async_graphql::dataloader::DataLoader::new(
            crate::api::schema::WorkflowNameLoader(db_pool.clone()),
            tokio::spawn,
        ))
        .data(async_graphql::dataloader::DataLoader::new(
            crate::api::schema::ActorNameLoader(db_pool.clone()),
            tokio::spawn,
        ))
        .data(async_graphql::dataloader::DataLoader::new(
            crate::api::schema::LatestExecutionLoader(db_pool.clone()),
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

// ---------- Seed templates ----------

/// Upsert a single built-in template.
///
/// Always updates `code_template` and `config_schema` so that rebuilding the
/// controller binary (which embeds templates via `include_str!`) keeps the DB
/// in sync without a manual DB wipe.  `category`, `description`, and `icon`
/// are only written on first insert.
pub(crate) async fn seed_templates(
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

        // The stable template identity: the on-disk directory name. This —
        // NOT the mutable display `name` — is the natural key for a catalog
        // template, so a renamed `display_name` updates the existing row
        // instead of minting a duplicate "twin".
        let catalog_slug = match path.file_name().and_then(|f| f.to_str()) {
            Some(s) => s.to_string(),
            None => {
                tracing::warn!("Skipping template '{}': unreadable directory name", name);
                continue;
            }
        };

        // Phase 5 / 2026-07-21 defect fix: seed the unified `modules` table
        // idempotently keyed on `catalog_slug` (rename-safe — prevents NEW
        // twins), returning whether the WASM needs (re)compilation. Unlike
        // the old name-keyed upsert, `needs_recompile` is true on a fresh
        // insert too (no WASM yet), which fixes the metadata-only first-seed
        // row that previously persisted with NULL wasm_bytes.
        let registered = talos_registry::reconcile::upsert_catalog_template_by_slug(
            &registry.db_pool,
            talos_registry::reconcile::CatalogUpsert {
                name: &name,
                category: &category,
                description: &description,
                config_schema: &config_schema,
                source_code: &code_template,
                allowed_hosts: &allowed_hosts,
                allowed_secrets: &allowed_secrets,
                requires_approval_for: &requires_approval_for,
                capability_world_long: &cw_long,
                catalog_slug: &catalog_slug,
            },
        )
        .await;

        match registered {
            Ok(reg) => {
                count += 1;
                // Recompile when the source changed OR the row still has no
                // WASM. On success, write the fresh bytes to EVERY row
                // sharing this slug (the shared catalog row AND any per-user
                // installs) so stale twins run new code without rewriting
                // any workflow graph_json.
                if reg.needs_recompile {
                    let pool_bg = registry.db_pool.clone();
                    let compiler_bg = compiler.clone();
                    let name_bg = name.clone();
                    let code_bg = code_template.clone();
                    let slug_bg = catalog_slug.clone();
                    tokio::spawn(async move {
                        tracing::info!(
                            template = %name_bg,
                            "Catalog template needs WASM — background compilation started"
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
                                    match talos_registry::reconcile::refresh_catalog_wasm_by_slug(
                                        &pool_bg,
                                        &slug_bg,
                                        &wasm_bytes,
                                        &hash,
                                    )
                                    .await
                                    {
                                        Ok(rows) => tracing::info!(
                                            template = %name_bg,
                                            bytes = bytes_len,
                                            rows_updated = rows,
                                            "Background compilation complete — refreshed all catalog twins for this template"
                                        ),
                                        Err(e) => tracing::warn!(
                                            template = %name_bg,
                                            error = %e,
                                            "Background compilation succeeded but DB update failed"
                                        ),
                                    }
                                }
                            }
                            Ok(result) => {
                                tracing::warn!(
                                    template = %name_bg,
                                    errors = ?result.errors,
                                    "Background compilation failed — keeping existing wasm_bytes"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    template = %name_bg,
                                    error = %e,
                                    "Background compilation error — keeping existing wasm_bytes"
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

    // Read-only duplicate-catalog reconciler: log any pre-existing twins and
    // the workflows referencing a stale one. Never rewrites user data.
    match talos_registry::reconcile::reconcile_duplicate_catalog_modules(&registry.db_pool).await {
        Ok(0) => {}
        Ok(n) => tracing::warn!(
            duplicate_sets = n,
            "catalog duplicate reconciler found duplicate module twins (see warnings above)"
        ),
        Err(e) => tracing::warn!(error = %e, "catalog duplicate reconciler failed"),
    }

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
pub(crate) async fn seed_marketplace(pool: &sqlx::PgPool) {
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
