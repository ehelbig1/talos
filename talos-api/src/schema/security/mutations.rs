//! GraphQL Mutation resolvers (MutationRoot).

use async_graphql::{Context, Result};
// use chrono::Utc; // unused
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;

#[allow(unused_imports)]
use crate::schema::types::*;
use crate::schema::{
    require_2fa, require_platform_admin, require_scope, validate_api_key_expires_in_days,
    SafeErrorExtensions,
};
// Removed unused imports: CompilationService, ParallelWorkflowEngine, encrypt_checkpoint

#[derive(Default)]
pub struct SecurityMutations;

#[async_graphql::Object]
impl SecurityMutations {
    async fn create_api_key(
        &self,
        ctx: &Context<'_>,
        input: CreateApiKeyInput,
    ) -> Result<ApiKeyCreated> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;

        let api_key_service = ctx.data::<Arc<talos_api_keys::ApiKeyService>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        // MCP-870 (2026-05-14): partition scopes into recognised / unknown
        // and reject the call when ANY string fails to parse. Pre-fix
        // `filter_map(...).collect()` silently dropped unknown variants,
        // so a caller submitting `["modules:read", "workflows:read"]`
        // (one phantom + one valid — exactly the MCP-847 phantom-scopes
        // shape from the talos-api-docs sweep) would get an api key
        // with only `WorkflowsRead` AND no error feedback. They'd
        // discover the dropped scope at request time as a confusing
        // "Insufficient API key permissions" 403 with no clue why.
        // Same misleading-partial-acceptance class as the
        // MCP-737/738/800/801/809/810 sweep but for input parsing.
        //
        // For PERSISTED scopes read from DB rows / headers,
        // `parse_api_key_scope_logged` (warn + skip) remains correct —
        // that path can't reject the row at read time. For FRESH USER
        // INPUT here, reject loudly so the caller knows their request
        // was malformed.
        let (recognised, unknown): (Vec<_>, Vec<_>) = input
            .scopes
            .iter()
            .map(|s| (s, talos_api_keys::ApiKeyScope::from_string(s)))
            .partition(|(_, parsed)| parsed.is_some());
        if !unknown.is_empty() {
            let unknown_csv = unknown
                .iter()
                .map(|(s, _)| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(async_graphql::Error::new(format!(
                "Unknown scope(s): {}. Valid scopes: {}",
                unknown_csv,
                talos_api_keys::ApiKeyScope::scopes_csv()
            ))
            .extend_safe());
        }
        let scopes: Vec<talos_api_keys::ApiKeyScope> = recognised
            .into_iter()
            .filter_map(|(_, parsed)| parsed)
            .collect();

        if scopes.is_empty() {
            // MCP-916 cont.: .extend_safe() — actionable validation error
            // would otherwise be scrubbed to "Internal server error" in
            // production.
            return Err(async_graphql::Error::new("At least one scope is required").extend_safe());
        }

        // MCP-769 (2026-05-13): canonical content discipline matching
        // MCP-186/MCP-431/MCP-747/MCP-748 + the `create_actor` shape
        // in actors/mutations.rs:135-184. Pre-fix the shallow
        // `is_empty() || len() > 255` check accepted:
        //   * whitespace-only names ("   ") that render blank in the
        //     audit log and `list_api_keys` UI — operator can't tell
        //     a real key from an accidental space
        //   * control chars (`\0`, BEL, VT, FF, ...) that corrupt the
        //     audit-log summary line and may crash downstream
        //     consumers parsing the JSON-quoted name (`\0` MCP-431)
        //   * leading/trailing whitespace that persists unchanged
        //     (the name field has no canonical-form invariant, so
        //     "  ci-token  " ≠ "ci-token" for lookup-by-name UX)
        // Sibling fix applied to `register_mcp_agent` below — both
        // are admin-scoped + 2FA-required and their name fields land
        // in `admin_event_log` summary text where DLP/parsing
        // assumptions matter.
        let trimmed_name = input.name.trim();
        if trimmed_name.is_empty() {
            return Err(async_graphql::Error::new(
                "API key name must be 1–255 characters (non-whitespace)",
            )
            .extend_safe());
        }
        if trimmed_name.len() > 255 {
            return Err(
                async_graphql::Error::new("API key name must be 1–255 characters").extend_safe(),
            );
        }
        talos_validation::reject_control_chars(
            "API key name",
            &input.name,
            talos_validation::LineMode::MultiLine,
        )
        .map_err(|e| async_graphql::Error::new(e.message).extend_safe())?;
        let name_owned = trimmed_name.to_string();

        // MCP-1187 (2026-05-17): bound expires_in_days at the
        // boundary. Pre-fix the raw Option<i64> reached chrono's
        // Duration::days(days) which panics on overflow (i64::MAX
        // would crash the API thread DoS-style) and accepts
        // negatives + zero (key minted in the past / immediately
        // expired). 1..=3650 matches workspace ceilings (10 years).
        validate_api_key_expires_in_days(input.expires_in_days)?;

        // Create the key - returns (full_key, id, expires_at) directly
        // This avoids the N+1 query of fetching all keys to find the new one
        let (key, id, expires_at) = api_key_service
            .create_api_key(*user_id, &name_owned, scopes.clone(), input.expires_in_days)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create API key: {}", e);
                async_graphql::Error::new("Failed to create API key").extend_safe()
            })?;

        let db_pool = ctx.data::<sqlx::PgPool>()?.clone();
        talos_actor_repository::spawn_log_admin_event(
            db_pool,
            *user_id,
            "api_key_created",
            "api_key",
            Some(id),
            format!(
                "API key '{}' created with scopes: {}",
                name_owned,
                scopes
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            None,
        );

        Ok(ApiKeyCreated {
            id,
            name: name_owned,
            key, // Full key - only shown once!
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            expires_at: expires_at.map(|dt| dt.to_rfc3339()),
        })
    }

    async fn revoke_api_key(&self, ctx: &Context<'_>, key_id: Uuid) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;

        let api_key_service = ctx.data::<Arc<talos_api_keys::ApiKeyService>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        api_key_service
            .revoke_key(key_id, *user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to revoke API key: {}", e);
                async_graphql::Error::new("Failed to revoke API key").extend_safe()
            })?;

        let db_pool = ctx.data::<sqlx::PgPool>()?.clone();
        talos_actor_repository::spawn_log_admin_event(
            db_pool,
            *user_id,
            "api_key_revoked",
            "api_key",
            Some(key_id),
            format!("API key {} revoked (deactivated)", key_id),
            None,
        );

        Ok(true)
    }

    async fn delete_api_key(&self, ctx: &Context<'_>, key_id: Uuid) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;

        let api_key_service = ctx.data::<Arc<talos_api_keys::ApiKeyService>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        api_key_service
            .delete_key(key_id, *user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to delete API key: {}", e);
                async_graphql::Error::new("Failed to delete API key").extend_safe()
            })?;

        let db_pool = ctx.data::<sqlx::PgPool>()?.clone();
        talos_actor_repository::spawn_log_admin_event(
            db_pool,
            *user_id,
            "api_key_deleted",
            "api_key",
            Some(key_id),
            format!("API key {} permanently deleted", key_id),
            None,
        );

        Ok(true)
    }

    async fn rotate_api_key(&self, ctx: &Context<'_>, key_id: Uuid) -> Result<ApiKeyCreated> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;

        let api_key_service = ctx.data::<Arc<talos_api_keys::ApiKeyService>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        // Get old key info first
        //
        // MCP-872 (2026-05-14): log the underlying error before
        // collapsing to the generic "API key not found" response.
        // Pre-fix the `.map_err(|_| ...)` discarded the sqlx error so
        // a DB outage / connection timeout / query bug looked
        // identical to a real "row missing or wrong user_id" hit on
        // the operator side. The user-facing message stays generic
        // (defense vs IDOR-probing for key existence), but server-
        // side logs now distinguish the three causes.
        let old_key = api_key_service
            .get_key(key_id, *user_id)
            .await
            .map_err(|e| {
                tracing::error!(
                    key_id = %key_id,
                    error = %e,
                    "rotate_api_key: get_key failed"
                );
                // MCP-964: lowercase 'n' in "not found" misses the
                // case-sensitive "Not found" whitelist substring.
                async_graphql::Error::new("API key not found").extend_safe()
            })?;

        // Rotate the key
        let new_key = api_key_service
            .rotate_key(key_id, *user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to rotate API key: {}", e);
                async_graphql::Error::new("Failed to rotate API key").extend_safe()
            })?;

        let db_pool = ctx.data::<sqlx::PgPool>()?.clone();
        talos_actor_repository::spawn_log_admin_event(
            db_pool,
            *user_id,
            "api_key_rotated",
            "api_key",
            Some(key_id),
            format!(
                "API key '{}' rotated (old key deactivated, new key issued)",
                old_key.name
            ),
            None,
        );

        Ok(ApiKeyCreated {
            id: key_id,
            name: old_key.name.clone(),
            key: new_key, // Full key - only shown once!
            scopes: old_key.scopes.iter().map(|s| s.to_string()).collect(),
            expires_at: old_key.expires_at.map(|dt| dt.to_rfc3339()),
        })
    }

    async fn rotate_dek(&self, ctx: &Context<'_>) -> Result<DekRotationResult> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;
        // System-wide: rotates the DEK that protects every tenant's
        // secrets. require_scope(Admin) session-bypasses, so add the
        // platform-admin gate.
        require_platform_admin(ctx).await?;

        let secrets_manager = ctx.data::<Arc<talos_secrets_manager::SecretsManager>>()?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let new_dek_id = secrets_manager
            .rotate_dek(Some(*user_id))
            .await
            .map_err(|e| {
                tracing::error!("Failed to rotate DEK: {}", e);
                async_graphql::Error::new("Failed to rotate DEK").extend_safe()
            })?;

        Ok(DekRotationResult {
            new_dek_id,
            message: "DEK rotated successfully. Run reEncryptSecrets to migrate existing secrets."
                .to_string(),
        })
    }

    async fn re_encrypt_secrets(&self, ctx: &Context<'_>) -> Result<ReEncryptionResult> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;
        // System-wide: re-encrypts every secret in the deployment.
        require_platform_admin(ctx).await?;

        let secrets_manager = ctx.data::<Arc<talos_secrets_manager::SecretsManager>>()?;

        let stats = secrets_manager.re_encrypt_secrets().await.map_err(|e| {
            tracing::error!("Failed to re-encrypt secrets: {}", e);
            async_graphql::Error::new("Failed to re-encrypt secrets").extend_safe()
        })?;

        // L T2-6: surface failure count + ids explicitly in the GraphQL
        // response. Pre-fix the operator would see "N secrets re-encrypted"
        // and miss any failures buried in server logs.
        let message = if stats.failed == 0 {
            format!(
                "{} secrets re-encrypted with active DEK",
                stats.re_encrypted
            )
        } else {
            format!(
                "{} re-encrypted, {} failed (still wrapped with non-active DEK). \
                 Inspect server logs and re-run after addressing the root cause.",
                stats.re_encrypted, stats.failed
            )
        };
        Ok(ReEncryptionResult {
            re_encrypted_count: stats.re_encrypted,
            failed_count: stats.failed,
            failed_ids: stats.failed_ids,
            message,
        })
    }

    async fn rotate_master_key(
        &self,
        ctx: &Context<'_>,
        new_master_key: String,
    ) -> Result<MasterKeyRotationResult> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;
        // CRITICAL: re-encrypts every DEK in the system with the
        // caller-supplied master key. Without this gate any 2FA-verified
        // user could submit a key they control, then an env-var mismatch
        // on the next restart would lock the deployment out of every
        // tenant's secrets. require_scope(Admin) session-bypasses, so we
        // need the platform-admin check.
        require_platform_admin(ctx).await?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        // Validate hex format: must be exactly 64 hex chars = 32 bytes
        if new_master_key.len() != 64 {
            return Err(async_graphql::Error::new(
                "New master key must be exactly 64 hex characters (32 bytes)",
            )
            .extend_safe());
        }

        // L-6: wrap the decoded 32-byte master key in `Zeroizing` so the
        // plaintext is wiped from this stack frame after `rotate_master_key`
        // moves the inner Vec into the new EnvKekProvider (which itself
        // stores the bytes in a `Zeroizing<Vec<u8>>` field).
        let new_key_bytes =
            talos_secrets_manager::Zeroizing::new(hex::decode(&new_master_key).map_err(|_| {
                async_graphql::Error::new("New master key must be a valid hex string")
                    .extend_safe()
                    .extend_safe()
            })?);

        let secrets_manager = ctx.data::<Arc<talos_secrets_manager::SecretsManager>>()?;

        let count = secrets_manager
            .rotate_master_key(new_key_bytes, Some(*user_id))
            .await
            .map_err(|e| {
                tracing::error!("Failed to rotate master key: {}", e);
                async_graphql::Error::new("Failed to rotate master key").extend_safe()
            })?;

        info!(
            dek_count = count,
            user_id = %user_id,
            "Master key rotated successfully"
        );

        Ok(MasterKeyRotationResult {
            re_encrypted_dek_count: count,
            message: format!(
                "Master key rotated successfully. {} DEKs re-encrypted. \
                 Update TALOS_MASTER_KEY env var to the new value before next restart.",
                count
            ),
        })
    }

    async fn rotate_encryption_key(&self, ctx: &Context<'_>) -> Result<i32> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;
        // System-wide: same blast radius as rotate_dek (legacy alias).
        require_platform_admin(ctx).await?;

        let secrets_manager = ctx
            .data::<Arc<talos_secrets_manager::SecretsManager>>()
            .map_err(|_| {
                async_graphql::Error::new("Secrets manager not configured").extend_safe()
            })?;
        let user_id = ctx.data_opt::<Uuid>().copied();

        // MCP-825 (2026-05-14): route through `rotate_dek` instead of the
        // broken `rotate_key` legacy alias.
        //
        // Pre-fix `secrets_manager.rotate_key()` queried the phantom
        // `data_encryption_keys` table (gone since the secrets-manager
        // extraction; only `encryption_keys` exists in current schema —
        // see migrations/001_initial_schema.sql:99). On new installs the
        // SELECT/UPDATE would 500; on legacy installs that still had
        // `data_encryption_keys`, the function only marked old rows
        // expiring and bumped a version counter, NEVER created a new
        // DEK. Either way, the operator clicking "Rotate Encryption Key"
        // in `SecretsManager.tsx` got a misleading-success toast
        // ("Key rotated to version N") while no actual DEK rotation
        // happened AND no audit row landed. Same misleading-success
        // class as MCP-737/738/800/801/809/810 — at the mutation-result
        // shape rather than the log shape.
        //
        // `rotate_dek` does the real work (advisory-lock-protected,
        // MCP-700: deactivates current DEK, inserts new active DEK,
        // logs `DEK_ROTATED` audit row, invalidates the in-memory
        // cache). Passes `Some(user_id)` for audit attribution.
        let new_dek_id = secrets_manager.rotate_dek(user_id).await.map_err(|e| {
            tracing::error!("DEK rotation failed: {}", e);
            async_graphql::Error::new("Key rotation failed").extend_safe()
        })?;

        // The frontend's `SecretsManager.tsx` toast displays the
        // returned integer as "Key rotated to version N". Use the
        // post-rotation count of `encryption_keys` rows — monotonically
        // increasing as long as old DEKs aren't pruned, which preserves
        // the operator's perception of "the number went up".
        let db_pool = ctx.data::<sqlx::PgPool>()?;
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM encryption_keys")
            .fetch_one(db_pool)
            .await
            .unwrap_or(1); // best-effort; the rotation itself already succeeded

        info!(
            new_dek_id = %new_dek_id,
            dek_count = count,
            user_id = ?user_id,
            "DEK rotation completed via GraphQL rotateEncryptionKey (MCP-825 routed to rotate_dek)"
        );

        Ok(count as i32)
    }

    async fn update_audit_settings(
        &self,
        ctx: &Context<'_>,
        streaming_enabled: bool,
        otlp_endpoint: Option<String>,
        otlp_protocol: Option<String>,
        auth_headers: Option<String>,
    ) -> Result<UserAuditSettings> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

        // MCP-866 (2026-05-14): reject otlp_protocol values that the
        // audit-ledger doesn't actually consume. Pre-fix the
        // `otlp_protocol` arg flowed straight into the INSERT with no
        // validation, but talos_audit_ledger::get_tracer always builds
        // the exporter via `with_tonic()` (gRPC) regardless of the
        // stored value. Users selecting "HTTP/Protobuf" in the
        // frontend dropdown got an "Audit settings updated"
        // success toast while audit batches silently went out via
        // gRPC — same misleading-success class as
        // MCP-737/738/800/801/809/810. Reject unsupported protocols at
        // the gate; the HTTP branch is a separate implementation lift
        // (different metadata-map type, different builder method)
        // that should land alongside its own e2e test, not as a
        // surprise behavior of an existing mutation.
        if let Some(ref proto) = otlp_protocol {
            if !proto.is_empty() && proto != "grpc" {
                return Err(async_graphql::Error::new(
                    "otlp_protocol: only 'grpc' is currently supported \
                     (HTTP/Protobuf is not yet wired through the audit-ledger exporter)",
                )
                .extend_safe());
            }
        }

        if let Some(ref ep) = otlp_endpoint {
            if ep.len() > 2048 {
                return Err(
                    async_graphql::Error::new("otlp_endpoint must be ≤ 2048 characters")
                        .extend_safe(),
                );
            }
            // MCP-773 (2026-05-13): SSRF check on the caller-supplied
            // OTLP endpoint. Pre-fix the only validation was length.
            // Any authenticated user (admin scope, but admin scope is
            // tenant-scoped not platform-scoped — every user with API
            // key admin access on their own tenant can hit this) could
            // set `otlp_endpoint = https://169.254.169.254/...` or
            // `https://internal-postgres:5432/...` and the controller's
            // audit-ledger subscriber would initiate outbound gRPC
            // connections to that target on every audit-event batch
            // (audit_ledger.rs:233 `SpanExporter::builder()
            // .with_endpoint(endpoint).build()`). Same canonical
            // helper used by every other outbound-URL config path
            // (webhooks, integrations, etc.) — `talos_http_utils::
            // check_outbound_url_no_ssrf` enforces https://,
            // RFC-3986-valid characters, no private/loopback/CGNAT/
            // link-local IPv4, no IPv6 ULA / link-local, no userinfo
            // bypass, no obfuscated IPv4 forms (octal / hex / int /
            // zero-padded). Same MCP-505/MCP-287/MCP-285 ssrf-check
            // surface — closes the OTLP exporter sibling.
            //
            // Note: the audit subsystem also reads the endpoint at
            // fire time (per-batch), so a write-time check is
            // necessary-but-not-sufficient against DNS-rebinding
            // attacks where a domain controlled by the user starts
            // resolving to a private IP AFTER the write succeeded.
            // Re-validation at fire time belongs in talos-audit-ledger
            // and is deferred — the write-time check alone closes the
            // direct-IP-literal abuse surface, which is the dominant
            // exploitation path. Audit dispatch is fire-and-forget
            // gRPC so the user has no observable response leak
            // regardless.
            if !ep.is_empty() {
                if let Err(reason) = talos_http_utils::ssrf::check_outbound_url_no_ssrf(ep) {
                    return Err(async_graphql::Error::new(format!(
                        "otlp_endpoint rejected: {reason}"
                    ))
                    .extend_safe());
                }
            }
        }

        let mut encrypted_headers = None;
        let mut headers_nonce = None;

        if let Some(headers) = auth_headers {
            if headers.len() > 100_000 {
                // MCP-916: extend_safe so the size-cap message survives
                // the production scrubber (no whitelist-substring match).
                return Err(
                    async_graphql::Error::new("auth_headers must be ≤ 100 KB").extend_safe()
                );
            }
            if !headers.is_empty() {
                // L3 (2026-05-28 review): encrypt with the canonical
                // `talos_audit_ledger` helper — an HKDF subkey of
                // TALOS_MASTER_KEY bound to this `user_id` via AAD — which is
                // the EXACT primitive the audit-ledger read path decrypts with.
                // Pre-L3 this used a SecretsManager DEK envelope while the read
                // path decrypted with the raw TALOS_MASTER_KEY, so the round
                // trip ALWAYS failed and the (silently-swallowed) result was
                // that authenticated audit streaming never worked. Both ends now
                // share one helper so they cannot drift.
                let (ciphertext, nonce) = talos_audit_ledger::encrypt_otlp_auth_headers(
                    &headers, *user_id,
                )
                .map_err(|_| {
                    // Opaque message — never leak crypto/internal detail.
                    async_graphql::Error::new(
                        "Failed to encrypt audit auth headers (is TALOS_MASTER_KEY configured?)",
                    )
                    .extend_safe()
                })?;
                encrypted_headers = Some(ciphertext);
                headers_nonce = Some(nonce);
            }
        }

        sqlx::query!(
            r#"
            INSERT INTO user_audit_settings (
                user_id, streaming_enabled, otlp_endpoint, otlp_protocol, 
                auth_headers_encrypted, auth_headers_nonce, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            ON CONFLICT (user_id) DO UPDATE SET
                streaming_enabled = EXCLUDED.streaming_enabled,
                otlp_endpoint = EXCLUDED.otlp_endpoint,
                otlp_protocol = EXCLUDED.otlp_protocol,
                auth_headers_encrypted = EXCLUDED.auth_headers_encrypted,
                auth_headers_nonce = EXCLUDED.auth_headers_nonce,
                updated_at = NOW()
            "#,
            user_id,
            streaming_enabled,
            otlp_endpoint,
            otlp_protocol,
            encrypted_headers,
            headers_nonce,
        )
        .execute(db_pool)
        .await?;

        let row = sqlx::query!(
            r#"
            SELECT streaming_enabled, otlp_endpoint, otlp_protocol, created_at, updated_at
            FROM user_audit_settings
            WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_one(db_pool)
        .await?;

        Ok(UserAuditSettings {
            streaming_enabled: row.streaming_enabled,
            otlp_endpoint: row.otlp_endpoint,
            otlp_protocol: row.otlp_protocol,
            created_at: row.created_at.to_rfc3339(),
            updated_at: row.updated_at.to_rfc3339(),
        })
    }
}
