//! GraphQL Mutation resolvers (MutationRoot).

use async_graphql::{Context, ErrorExtensions, Result};
use sha2::Digest;
use std::sync::Arc;
use uuid::Uuid;

use super::super::{require_2fa, require_scope, SafeErrorExtensions};
use crate::schema::types::*;
use talos_compilation::CompilationService;
use talos_registry::ModuleRegistry;
use talos_workflow_engine::ParallelWorkflowEngine;
use worker::TalosRuntime;

#[derive(Default)]
pub struct ModulesMutations;

#[async_graphql::Object]
impl ModulesMutations {
    async fn create_module_from_template(
        &self,
        ctx: &Context<'_>,
        input: CreateModuleInput,
    ) -> Result<WasmModule> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;

        let registry: &Arc<ModuleRegistry> = ctx.data::<Arc<ModuleRegistry>>()?;
        let compiler = ctx.data::<Arc<CompilationService>>()?;
        let secrets_manager = ctx.data::<Arc<talos_secrets_manager::SecretsManager>>()?;

        // Get authenticated user_id from context
        // MCP-793 (2026-05-14): user-scoped template lookup. Pre-fix this
        // called the unscoped `get_template(id)` which executed
        // `WHERE id = $1` with no user_id filter — letting any
        // authenticated user fetch the source_code, allowed_hosts,
        // allowed_secrets, capability_world, and config of any other
        // user's private template by knowing its UUID. Worse than the
        // sibling `node_template` query (MCP-793 (2)) which returns
        // limited metadata: THIS handler then uses `template.code_template`
        // as the source for compilation (line ~178 below) and persists
        // the resulting WASM under the calling user's account. Two
        // exploits collapsed into one mutation:
        //   (a) Source-code disclosure of any user's private template.
        //   (b) Code reuse — create a fully-functional module instance
        //       backed by another user's WASM/source under the
        //       attacker's account, bypassing whatever access controls
        //       the original owner intended.
        // `get_template_for_user(id, user_id)` adds `AND (user_id IS NULL
        // OR user_id = $2)`, so catalog templates (NULL owner) remain
        // accessible to everyone while private templates resolve only
        // for their owner. Same scope fix shape as MCP-589/662/675
        // (indirect-grant SQL paths must scope by user_id).
        let (user_id, template) = {
            let user_id = ctx.data::<Uuid>()?;
            // MCP-963 (2026-05-15): log underlying error server-side
            // and return a generic message marked `.extend_safe()` so
            // it survives the production scrubber. Pre-fix
            // `map_err(|e| async_graphql::Error::new(e.to_string()))`:
            // (a) the `e.to_string()` came from `get_template_for_user`
            // which wraps sqlx errors with `.context("Template not
            // found or access denied")`, so the message string was
            // "Template not found or access denied[: <sqlx detail>]"
            // — case-sensitive "Not found" whitelist does NOT match
            // lowercase "not found", so production-scrubber replaces
            // the message with "Internal server error" and operators
            // chase ghosts. (b) On real DB errors the chain may
            // include schema/connection detail that's not appropriate
            // for client responses. Generic "Template not found or
            // access denied" works for both cases; full error goes
            // to tracing::error.
            let template = registry
                .get_template_for_user(input.template_id, *user_id)
                .await
                .map_err(|e| {
                    tracing::error!(
                        template_id = %input.template_id,
                        error = %e,
                        "create_module_from_template: get_template_for_user failed"
                    );
                    async_graphql::Error::new("Template not found or access denied")
                        .extend_safe()
                        .extend_safe()
                })?;
            (*user_id, template)
        };

        // MCP-832 (2026-05-14): MCP-769 sweep — replace shallow length-only
        // check with focused content-discipline via `validate_display_name`
        // (trim + reject empty-after-trim + length cap + control-char /
        // `\0` rejection). Module name is rendered in the dashboard +
        // logs; pre-fix `name: "   "` persisted as whitespace and `\0`
        // embedded names crashed downstream UPDATEs (MCP-431).
        let trimmed_name = crate::schema::validate_display_name("Module name", &input.name, 200)?;
        let module_name = trimmed_name.to_string();
        if input.config.len() > 100_000 {
            // MCP-916: extend_safe so production scrubber doesn't replace
            // this with "Internal server error" — no overlap with the
            // whitelist substrings, so operators submitting an oversized
            // config previously saw a generic error and couldn't fix
            // their input.
            return Err(async_graphql::Error::new("config must be ≤ 100 KB").extend_safe());
        }
        // 2. Parse config
        let config: serde_json::Value = serde_json::from_str(&input.config).map_err(|e| {
            tracing::error!("Invalid JSON config: {}", e);
            async_graphql::Error::new("Invalid JSON config").extend_safe()
        })?;

        // 2b. Validate config SHAPE against the template's config_schema
        // BEFORE compiling. Pre-fix a shape mistake (e.g. HEADERS supplied
        // as a `{key: value}` object instead of the schema's
        // `[{key, value}]` array) sailed through create + compile and only
        // failed deep inside the WASM guest at RUN time as
        // "Invalid JSON input: invalid type: map, expected a sequence" —
        // an opaque error a caller can't map back to their config. The
        // validator (type / enum / required, shared with MCP via
        // talos-validation) turns that into an actionable create-time
        // message naming the offending key. Message is caller-input, safe
        // to surface via extend_safe.
        talos_validation::validate_config_against_schema(&config, &template.config_schema)
            .map_err(|e| async_graphql::Error::new(e.message).extend_safe())?;

        // 3. Extract secret references and validate they exist.
        // MCP-662 (2026-05-13): bulk-validate via
        // `existing_secret_key_paths(paths, user_id)` instead of
        // per-path `secret_exists`. The previous loop had TWO issues:
        //
        //   (a) **N+1 queries** — 50 referenced secrets = 50 sequential
        //       round trips to the DB before any compile/persist work.
        //
        //   (b) **Information leak** — `secret_exists` scans the
        //       secrets table without a `created_by` predicate, so it
        //       reported existence of secrets the calling user does
        //       not own. An attacker could probe arbitrary paths
        //       (e.g. `admin/sk_key`) and learn whether the platform
        //       admin had registered them. The runtime resolver
        //       (`get_module_secrets_for_user`) IS user-scoped (per
        //       MCP-589), so the pre-flight gate was looser than the
        //       runtime gate — a module could be created referencing
        //       paths the user couldn't actually resolve at dispatch,
        //       and the existence probe leaked path metadata in the
        //       error message.
        //
        // Both fixed by routing through the batched + user-scoped
        // helper. Reports the first missing path for caller-friendly
        // UX without enumerating every miss.
        let secret_refs = talos_secrets_manager::extract_secret_references(&config);
        if !secret_refs.is_empty() {
            let existing = secrets_manager
                .existing_secret_key_paths(&secret_refs, user_id)
                .await?;
            if let Some(missing) = secret_refs.iter().find(|p| !existing.contains(*p)) {
                // MCP-918: .extend_safe() — actionable "create it first"
                // guidance lost otherwise.
                return Err(async_graphql::Error::new(format!(
                    "Secret not found: {}. Please create it first.",
                    missing
                ))
                .extend_safe());
            }
        }

        // 4. Use precompiled WASM if available, otherwise compile template
        let mut oci_url_opt: Option<String> = None;

        let (
            wasm_bytes,
            source_code,
            size_bytes,
            content_hash,
            capability_world,
            imported_interfaces,
        ) = if let Some(precompiled) = template.precompiled_wasm.clone() {
            // Use precompiled template WASM
            let precompiled_len = precompiled.len() as i32;
            let mut hasher = sha2::Sha256::new();
            hasher.update(&precompiled);
            let hash = format!("{:x}", hasher.finalize());
            let inspection = worker::inspect_component(&precompiled);

            (
                precompiled,
                template.code_template.clone(),
                precompiled_len,
                hash,
                inspection.capability_world,
                inspection.imported_interfaces,
            )
        } else if let Some(ref url) = template.oci_url {
            // It's an OCI image - we don't compile anything, and we don't store WASM bytes.
            // The Worker will pull the image from the registry and inspect it at runtime.
            oci_url_opt = Some(url.to_string());

            // We use a dummy hash since it's fetched at runtime
            let mut hasher = sha2::Sha256::new();
            hasher.update(url.as_bytes());
            hasher.update(
                serde_json::to_string(&config)
                    .unwrap_or_default()
                    .as_bytes(),
            );
            hasher.update(Uuid::new_v4().to_string().as_bytes()); // Force uniqueness to bypass WASM deduplication layer
            let hash = format!("{:x}", hasher.finalize());

            (
                vec![],         // Empty WASM bytes
                "".to_string(), // Empty source
                0,
                hash,
                worker::CapabilityWorld::Unknown, // Worker will determine this at runtime
                vec![],
            )
        } else {
            // Compile template with config rendering
            // Config is rendered into template at compile-time for optimal performance
            let job_id = input.job_id.unwrap_or_else(Uuid::new_v4);
            let result = compiler
                .compile_to_wasm_with_config(
                    user_id,
                    job_id,
                    &module_name,
                    &template.code_template,
                    &config,
                    None,
                )
                .await
                .map_err(|e| {
                    tracing::error!("Compilation failed: {}", e);
                    async_graphql::Error::new("Compilation failed").extend_safe()
                })?;

            if !result.success {
                let error_messages: Vec<String> =
                    result.errors.iter().map(|e| e.message.clone()).collect();
                // MCP-918: chain .extend_safe() after .extend_with so
                // operators see the compiler errors instead of "Internal
                // server error" — same UX class as test_module size cap.
                return Err(async_graphql::Error::new("Compilation failed")
                    .extend_safe()
                    .extend_with(|_, e| e.set("errors", error_messages))
                    .extend_safe());
            }

            (
                result.wasm_bytes.ok_or_else(|| {
                    async_graphql::Error::new("Missing wasm bytes in compilation result")
                        .extend_safe()
                })?,
                template.code_template.clone(),
                result.size_bytes,
                result.content_hash,
                result.capability_world,
                result.imported_interfaces,
            )
        };

        // 5. Store module with config as metadata
        let module = talos_registry::WasmModule {
            name: module_name.clone(),
            content_hash,
            capability_world,
            imported_interfaces,
            allowed_methods: vec![],
            wasm_bytes,
            source_code: Some(source_code),
            template_id: Some(input.template_id),
            config: Some(config.clone()), // Config stored as metadata, NOT compiled into WASM
            dependencies: None,
            size_bytes,
            max_fuel: 1_000_000,
            max_memory_mb: 128,
            allowed_hosts: template.allowed_hosts.clone(),
            allowed_secrets: template.allowed_secrets.clone(),
            requires_approval_for: template.requires_approval_for.clone(),
            user_id: Some(user_id),
            oci_url: oci_url_opt,
            language: "rust".to_string(),
            integration_name: None,
        };

        let module_id = registry.store_module(module.clone()).await?;

        // AUTO-SETUP: Create Google Calendar watch channels for webhook nodes
        if template.category == "calendar" && template.name.contains("Webhook") {
            tracing::info!(
                "🔧 Auto-setting up Google Calendar webhook for module {}",
                module_id
            );

            // Extract integration and calendar IDs from config
            tracing::debug!(
                "Config keys: {:?}",
                config.as_object().map(|o| o.keys().collect::<Vec<_>>())
            );

            if let (Some(integration_id_str), Some(calendar_ids)) = (
                config
                    .get("GOOGLE_CALENDAR_INTEGRATION_ID")
                    .and_then(|v| v.as_str()),
                config.get("CALENDAR_IDS").and_then(|v| v.as_array()),
            ) {
                tracing::info!(
                    "Found integration_id: {}, calendars: {:?}",
                    integration_id_str,
                    calendar_ids
                );

                if let Ok(integration_id) = Uuid::parse_str(integration_id_str) {
                    tracing::info!("Parsed integration UUID: {}", integration_id);

                    // SECURITY: Verify the user owns this integration before creating watch channels
                    // This prevents users from creating watch channels using other users' credentials.
                    //
                    // MCP-840 (2026-05-14): distinguish DB error from
                    // "doesn't own". Pre-fix `.unwrap_or(false)` collapsed
                    // every failure into `owns_integration = false`,
                    // which then fired the 🚨 SECURITY warn log accusing
                    // the user of attempting to use an integration they
                    // don't own — even when the user DID own it and
                    // the SELECT just hiccupped. Two harms: (a) false
                    // security alarms during DB blips waste on-call
                    // investigation time; (b) the module is created
                    // either way but the watch channel auto-setup
                    // silently skips, leaving the user with a half-
                    // configured module they think is wired up. Same
                    // misleading-discriminator class as MCP-838/839
                    // applied to a security-log surface.
                    let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;
                    // Tri-state: Some(true) = Owned, Some(false) = NotOwned
                    // (security event), None = ProbeFailed (DB error already
                    // logged inline). Both falsy paths skip the watch-channel
                    // setup but only the NotOwned arm fires the SECURITY warn.
                    let ownership: Option<bool> =
                        match talos_google_calendar::user_owns_active_integration(
                            db_pool,
                            integration_id,
                            user_id,
                        )
                        .await
                        {
                            Ok(v) => Some(v),
                            Err(e) => {
                                tracing::error!(
                                    target: "talos_audit",
                                    %user_id,
                                    %integration_id,
                                    error = %e,
                                    "create_module_from_template: failed to verify integration ownership — skipping watch-channel auto-setup (the module IS still created)"
                                );
                                None
                            }
                        };

                    if ownership == Some(false) {
                        tracing::warn!(
                            "🚨 SECURITY: User {} attempted to use integration {} they don't own. Skipping auto-setup.",
                            user_id, integration_id
                        );
                        // Continue with module creation but skip watch channel setup
                        // This prevents the entire mutation from failing
                    } else if ownership == Some(true) {
                        // Get Google Calendar service
                        match ctx.data::<Arc<talos_google_calendar::GoogleCalendarService>>() {
                            Ok(google_calendar_service) => {
                                tracing::info!("Got Google Calendar service from context");
                                // MCP-765 (2026-05-13): empty-env hardening —
                                // see `talos-google-calendar::handlers.rs::create_watch_handler`
                                // and `admin.rs:143` for the canonical
                                // explanation. `BASE_URL=""` made `webhook_url`
                                // a relative path that Google rejected at
                                // watch-channel creation. Same fix shape as
                                // MCP-630/631/653.
                                // MCP-1155: canonical helper — empty-env
                                // handling + open-redirect-misconfig
                                // defense moved into talos_config.
                                let base_url = talos_config::get_base_url();
                                let webhook_url =
                                    format!("{}/api/google-calendar/webhook", base_url);

                                let mut watch_channel_ids = Vec::new();
                                let mut errors = Vec::new();

                                // Create watch channel for each calendar
                                for calendar_id_val in calendar_ids {
                                    if let Some(calendar_id) = calendar_id_val.as_str() {
                                        match google_calendar_service
                                            .create_watch_channel(
                                                integration_id,
                                                calendar_id,
                                                &webhook_url,
                                                Some(module_id),
                                            )
                                            .await
                                        {
                                            Ok(channel) => {
                                                tracing::info!(
                                            "✅ Created watch channel {} for calendar {} (expires: {})",
                                            channel.id, calendar_id, channel.expiration
                                        );
                                                watch_channel_ids.push(serde_json::json!({
                                                    "id": channel.id.to_string(),
                                                    "calendar_id": calendar_id,
                                                    "channel_id": channel.channel_id,
                                                    "expiration": channel.expiration.to_rfc3339(),
                                                }));
                                            }
                                            Err(e) => {
                                                let error_msg =
                                                    format!("Calendar '{}': {}", calendar_id, e);
                                                tracing::warn!(
                                                    "⚠️ Failed to create watch channel: {}",
                                                    error_msg
                                                );
                                                errors.push(error_msg);
                                            }
                                        }
                                    }
                                }

                                // Update module config with created watch channels
                                if !watch_channel_ids.is_empty() {
                                    let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;
                                    let updated_config = {
                                        let mut cfg = config.clone();
                                        cfg["WATCH_CHANNELS"] =
                                            serde_json::json!(watch_channel_ids);
                                        cfg
                                    };

                                    // CRITICAL: Handle database update errors properly
                                    // If this fails, we have orphaned watch channels in Google Calendar
                                    //
                                    // Phase 5.1: write to unified `modules` table by canonical id.
                                    let module_repo =
                                        talos_module_repository::ModuleRepository::new(
                                            db_pool.clone(),
                                        );
                                    match module_repo
                                        .update_module_config(module_id, &updated_config)
                                        .await
                                    {
                                        Ok(_) => {
                                            tracing::info!(
                                        "✅ Auto-setup complete: {} watch channel(s) created for module {}",
                                        watch_channel_ids.len(), module_id
                                    );
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                        "❌ CRITICAL: Failed to update module config with watch channels: {}. Cleaning up orphaned channels.",
                                        e
                                    );

                                            // Clean up orphaned watch channels to prevent resource leaks
                                            let mut cleanup_tasks = vec![];
                                            for watch_info in &watch_channel_ids {
                                                if let Some(id_str) =
                                                    watch_info.get("id").and_then(|v| v.as_str())
                                                {
                                                    if let Ok(channel_uuid) =
                                                        Uuid::parse_str(id_str)
                                                    {
                                                        let service = std::sync::Arc::clone(
                                                            google_calendar_service,
                                                        );
                                                        let owner = user_id;
                                                        cleanup_tasks.push(tokio::spawn(async move {
                                                            match service.stop_watch_channel(owner, channel_uuid).await {
                                                                Ok(_) => tracing::info!("✅ Cleaned up orphaned watch channel {}", channel_uuid),
                                                                Err(err) => tracing::error!("❌ Failed to cleanup orphaned watch channel {}: {}", channel_uuid, err),
                                                            }
                                                        }));
                                                    }
                                                }
                                            }
                                            futures::future::join_all(cleanup_tasks).await;

                                            errors.push(format!(
                                                "Failed to save watch channel configuration: {}",
                                                e
                                            ));
                                        }
                                    }
                                }

                                // If there were partial failures, log them but don't fail the mutation
                                if !errors.is_empty() {
                                    tracing::warn!(
                                        "⚠️ Some watch channels failed to create: {}",
                                        errors.join("; ")
                                    );
                                }
                            }
                            Err(_) => {
                                tracing::warn!("⚠️ Google Calendar service not available in GraphQL context for auto-setup");
                            }
                        }
                    } // End of authorization check block
                } else {
                    tracing::warn!(
                        "⚠️ Failed to parse integration_id as UUID: {}",
                        integration_id_str
                    );
                }
            } else {
                tracing::warn!(
                    "⚠️ Missing GOOGLE_CALENDAR_INTEGRATION_ID or CALENDAR_IDS in config"
                );
            }
        }

        Ok(WasmModule {
            id: module_id,
            name: module.name,
            size_bytes: module.size_bytes,
            content_hash: module.content_hash,
            compiled_at: chrono::Utc::now().to_rfc3339(),
            config: module
                .config
                .map(|c| c.to_string())
                .unwrap_or_else(|| "{}".to_string()),
            // Compile response: the registry module type carries no config
            // schema; clients needing it re-query wasmModules after compile.
            config_schema: None,
            capability_world: Some(module.capability_world.to_string()),
            imported_interfaces: Some(module.imported_interfaces),
            source_code: None,
            language: Some(module.language),
        })
    }

    async fn test_module(
        &self,
        ctx: &Context<'_>,
        module_id: Uuid,
        input: Option<String>,
        timeout_secs: Option<i32>,
    ) -> Result<TestModuleResult> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let runtime = ctx.data::<Arc<TalosRuntime>>()?;
        let registry: &Arc<ModuleRegistry> = ctx.data::<Arc<ModuleRegistry>>()?;

        let timeout =
            std::time::Duration::from_secs(timeout_secs.unwrap_or(30).clamp(1, 120) as u64);

        let start = std::time::Instant::now();

        // Load the module (try wasm_modules first, then node_templates precompiled)
        let module: talos_registry::WasmModule =
            registry.get_module(module_id, user_id).await.map_err(|e| {
                tracing::error!("Failed to load module {}: {}", module_id, e);
                async_graphql::Error::new("Module not found or access denied").extend_safe()
            })?;

        // MCP-868 (2026-05-14): size-cap the input JSON before parsing,
        // mirroring `test_workflow.mock_inputs` (MCP-666). Pre-fix
        // `serde_json::from_str(json_str)` would force a multi-MB
        // allocation proportional to the input before the parser
        // got a chance to reject malformed content — a 2FA-scoped
        // user with a buggy client (or a hostile internal actor) could
        // submit a 100MB string and stall the controller process on
        // allocation. 1_000_000 bytes (1 MB decimal, same constant as
        // `TRIGGER_INPUT_MAX_BYTES` in talos-execution-orchestration)
        // covers every legitimate test-module payload — module inputs
        // are typically a handful of KB, not megabytes.
        let input_val: serde_json::Value = match &input {
            Some(json_str) => {
                const TEST_MODULE_INPUT_MAX_BYTES: usize = 1_000_000;
                if json_str.len() > TEST_MODULE_INPUT_MAX_BYTES {
                    return Err(async_graphql::Error::new(format!(
                        "input must be ≤ {} bytes when serialised (got {})",
                        TEST_MODULE_INPUT_MAX_BYTES,
                        json_str.len()
                    ))
                    .extend_safe());
                }
                serde_json::from_str(json_str).map_err(|e| {
                    async_graphql::Error::new(format!("Invalid input JSON: {}", e)).extend_safe()
                })?
            }
            None => serde_json::json!({}),
        };

        // Build payload
        let payload = {
            let mut merged = serde_json::Map::new();
            if let Some(obj) = input_val.as_object() {
                for (k, v) in obj {
                    merged.insert(k.clone(), v.clone());
                }
            }
            if !input_val.is_null() && input_val != serde_json::json!({}) {
                merged.insert("config".to_string(), input_val);
            }
            serde_json::Value::Object(merged)
        };

        let execution_result = runtime
            .execute_job_with_full_features(
                &module.wasm_bytes,
                module.allowed_hosts.clone(),
                module.allowed_methods.clone(),
                module.max_memory_mb as usize,
                payload,
                None,
                None,
                std::collections::HashMap::new(),
                None,
                timeout,
                worker::runtime::RetryPolicy::default(),
                None,
                worker::runtime::SecurityPolicy::default(),
                None,                                             // capability_world_hint
                None,                                             // max_fuel_override
                false,                                            // dry_run
                None,                                             // actor_id
                uuid::Uuid::nil(), // user_id (controller-internal test path)
                talos_workflow_job_protocol::LlmTier::default(), // tier2 for internal tests
                talos_workflow_job_protocol::WriteCeiling::Write, // permissive: internal test path
            )
            .await;

        let duration_ms = start.elapsed().as_millis() as u64;

        match execution_result {
            Ok(val) => {
                let output = ParallelWorkflowEngine::unwrap_output(&val);
                Ok(TestModuleResult {
                    success: true,
                    output: Some(output.to_string()),
                    error: None,
                    duration_ms,
                })
            }
            Err(e) => Ok(TestModuleResult {
                success: false,
                output: None,
                error: Some(format!("{}", e)),
                duration_ms,
            }),
        }
    }
}
