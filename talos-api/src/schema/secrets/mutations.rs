//! GraphQL Mutation resolvers (MutationRoot).
//!
//! MCP-1201 (2026-05-17): this file is the SOLE writer of secret rows.
//! The previously-mirrored `handle_set_secret` / `handle_delete_secret`
//! / `handle_set_secret_namespace` / `handle_set_secret_expiry` /
//! `handle_rotate_secret` MCP handlers were removed — MCP API keys
//! carry long-lived bearer tokens with no 2FA equivalent, so routing
//! secret writes through MCP would have bypassed the
//! `require_2fa + SecretsWrite` discipline this file enforces. The
//! "mirrors `handle_set_secret`" / "matches MCP ceiling" comments
//! below are historical references explaining where the
//! validator/cap rules originally came from — they remain accurate
//! as a description of the rules themselves, even though the
//! sibling implementation no longer exists.

use async_graphql::{Context, Object, Result};
use std::sync::Arc;
use uuid::Uuid;

use crate::schema::types::*;
use crate::schema::{
    require_2fa, require_scope, validate_resource_name, validate_secret_value,
    validate_vault_key_path, ApiKeyOrgScope, SafeErrorExtensions,
};
// Removed unused imports: CompilationService, ParallelWorkflowEngine, encrypt_checkpoint

#[derive(Default)]
pub struct SecretsMutations;

#[Object]
impl SecretsMutations {
    async fn create_secret(&self, ctx: &Context<'_>, input: CreateSecretInput) -> Result<Secret> {
        crate::schema::require_2fa(ctx)?;
        crate::schema::require_scope(ctx, talos_api_keys::ApiKeyScope::SecretsWrite)?;

        // SECURITY: Validate input lengths to prevent DoS
        validate_resource_name(&input.name)?;
        // MCP-1003 (2026-05-15): validate `key_path` via the canonical
        // helper that mirrors `handle_set_secret` in MCP — lowercase
        // ASCII alphanumeric + `-_/` only, 1-200 chars, no leading/
        // trailing `/`, no `//`. Pre-fix `validate_short_text_field`
        // only checked length, so GraphQL accepted shapes the MCP
        // sibling refused (uppercase, control chars, consecutive
        // slashes), and the resulting secret would be functionally
        // unreachable from `vault_path_permitted` matchers that follow
        // the documented lowercase/single-slash convention.
        validate_vault_key_path(&input.key_path).map_err(|e| e.extend_safe())?;
        // MCP-1186 (2026-05-17): canonical 64 KiB cap + whitespace-only
        // reject (folded into one helper). Pre-fix `validate_text_field`
        // capped at 1 MiB — 16× the MCP `handle_set_secret` ceiling
        // and 16× the `talos_actor_memory_service::MAX_VALUE_BYTES`
        // canonical. Same cross-protocol validation-drift class as
        // MCP-1003 (key_path).
        validate_secret_value(&input.value)?;
        // MCP-833: mirror MCP `handle_set_secret` description contract
        // (cap 5000, reject whitespace-only). MCP-837 (2026-05-14):
        // routed through canonical `validate_description_content`
        // helper so the 4-step shape lives in one place.
        let description = match input.description {
            None => None,
            Some(ref d) if d.is_empty() => None,
            Some(ref d) => Some(
                crate::schema::validate_description_content("description", d, 5000)?.to_string(),
            ),
        };

        // MCP-750 (2026-05-13): port three secret-validation gaps from
        // MCP `handle_set_secret` (talos-mcp-handlers/src/secrets.rs:312):
        //
        // (1) MCP-231: trim name at the boundary so the bound name
        //     matches what `get_secret(name: "github_token")` sees from
        //     MCP / CLI / SDK. `validate_resource_name` above checks
        //     `trimmed.len()` but the caller used to bind the un-
        //     trimmed `&input.name` into `SecretsManager::create_secret`,
        //     persisting "  github_token  " literally — dashboard row
        //     visible but every read path missed.
        //
        // (2) MCP-272: reject whitespace-only secret VALUE.
        //     `validate_text_field` only caps length, accepting
        //     `value: "   "` — operator typo persists a useless secret
        //     that every consumer module receives as whitespace instead
        //     of credentials.
        //
        // MCP-751 (2026-05-13): the control-char and `\0` rejection on
        // the NAME now lives in `validate_resource_name` itself (above
        // call) so every caller of the helper inherits the tighter
        // policy. The inline check that originally lived here was
        // redundant after MCP-751.
        //
        // Same GraphQL-mirror-MCP per-field-validation pattern as
        // MCP-747/MCP-748/MCP-749.
        let trimmed_name = input.name.trim();
        // MCP-1186 (2026-05-17): whitespace-only reject folded into
        // `validate_secret_value` above; the redundant inline check
        // would now be unreachable.

        let secrets_manager = ctx.data::<Arc<talos_secrets_manager::SecretsManager>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // If the request is org-scoped (org API key), assign the secret to that org.
        // Otherwise honor the caller-supplied org_id but verify the caller is a
        // writable member of that org — without this check, any user could plant
        // a secret with an arbitrary org_id (e.g. `key_path=anthropic/api_key,
        // org_id=<some other org>`), and members of that org reading the same
        // key_path via their workflows would resolve the attacker's controlled
        // value: cross-org credential injection.
        let org_id = if let Ok(org_scope) = ctx.data::<ApiKeyOrgScope>() {
            Some(org_scope.0)
        } else if let Some(target_org) = input.org_id {
            let writable = crate::schema::user_writable_org_ids(ctx).await?;
            if !writable.contains(&target_org) {
                // MCP-918: .extend_safe()
                return Err(async_graphql::Error::new(
                    "You are not a writable member of the requested org_id",
                )
                .extend_safe());
            }
            Some(target_org)
        } else {
            None
        };

        let secret_id = secrets_manager
            .create_secret(
                trimmed_name, // MCP-750: trimmed at the boundary (MCP-231 parity)
                &input.key_path,
                &input.value,
                description.as_deref(), // MCP-833: validated + trimmed
                *user_id,               // Set creator to current user
                input.allowed_modules.unwrap_or_default(),
                org_id,
            )
            .await?;

        // L T2-1: ownership filter is at the SQL layer. Pass the
        // creator user_id (set as both owner_user_id AND created_by
        // during create_secret); accessible_org_ids only needs to
        // include the explicit `org_id` we just bound, since this is
        // the immediate post-create round-trip.
        let post_create_orgs: Vec<uuid::Uuid> = org_id.into_iter().collect();
        let secret = secrets_manager
            .get_secret_metadata(&input.key_path, *user_id, &post_create_orgs)
            .await?;

        Ok(Secret {
            id: secret_id,
            name: secret.name,
            key_path: secret.key_path,
            description: secret.description,
            created_at: secret.created_at.to_rfc3339(),
            last_accessed_at: secret.last_accessed_at.map(|dt| dt.to_rfc3339()),
            access_count: secret.access_count,
            expires_at: secret.expires_at.map(|dt| dt.to_rfc3339()),
        })
    }

    async fn update_secret(&self, ctx: &Context<'_>, input: UpdateSecretInput) -> Result<Secret> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::SecretsWrite)?;

        // MCP-1003: canonical key_path validation (see create_secret
        // above for the full rationale). Strict charset + length +
        // shape mirrors `handle_set_secret`.
        validate_vault_key_path(&input.key_path).map_err(|e| e.extend_safe())?;
        // MCP-829 (2026-05-14) + MCP-1186 (2026-05-17): whitespace-only
        // reject AND 64 KiB cap folded into one canonical helper.
        // Pre-fix `validate_text_field` capped at 1 MiB and the
        // whitespace check was an inline gate below; the two-layer
        // shape was vulnerable to drift between create_secret (which
        // had its own inline whitespace check) and any future sibling.
        // `validate_secret_value` now mirrors MCP `handle_set_secret`
        // exactly: trim-empty-rejects, 64 KiB cap, value-internal
        // whitespace preserved (multi-line PEM keys legitimately
        // carry trailing newlines).
        validate_secret_value(&input.value)?;

        let secrets_manager = ctx.data::<Arc<talos_secrets_manager::SecretsManager>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // update_secret is a write — Viewer must not be able to overwrite
        // org-shared secret values. Use role-filtered helper.
        let org_ids: Vec<uuid::Uuid> = crate::schema::user_writable_org_ids(ctx).await?;

        // L T2-1: existence + ownership check fused into one SQL call.
        // Pre-fix the existence check ran first via `get_secret_metadata`
        // (no filter) and returned a distinguishable error; the post-
        // fetch ownership check ran in Rust. Now the SQL filter handles
        // both: a not-found-or-access-denied result returns the same
        // "Secret not found" string from the manager.
        // MCP-872 (2026-05-14): log the underlying error before
        // collapsing to the generic "Secret not found" response so
        // operators can tell DB / decryption / permission failures
        // apart from real not-found hits. User-facing message stays
        // generic per the L T2-1 no-existence-side-channel comment.
        let _existence_check: talos_secrets_manager::Secret = secrets_manager
            .get_secret_metadata(&input.key_path, *user_id, &org_ids)
            .await
            .map_err(|e| {
                tracing::error!(
                    key_path = %input.key_path,
                    error = %e,
                    "update_secret existence_check failed"
                );
                // MCP-964: lowercase 'n' in "not found" misses
                // the case-sensitive "Not found" whitelist substring.
                async_graphql::Error::new("Secret not found").extend_safe()
            })?;

        secrets_manager
            .update_secret(&input.key_path, &input.value, Some(*user_id), &org_ids)
            .await?;

        let secret: talos_secrets_manager::Secret = secrets_manager
            .get_secret_metadata(&input.key_path, *user_id, &org_ids)
            .await?;

        Ok(Secret {
            id: secret.id,
            name: secret.name,
            key_path: secret.key_path,
            description: secret.description,
            created_at: secret.created_at.to_rfc3339(),
            last_accessed_at: secret.last_accessed_at.map(|dt| dt.to_rfc3339()),
            access_count: secret.access_count,
            expires_at: secret.expires_at.map(|dt| dt.to_rfc3339()),
        })
    }

    async fn delete_secret(&self, ctx: &Context<'_>, key_path: String) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::SecretsWrite)?;

        // MCP-1003: canonical key_path validation (see create_secret
        // above for the full rationale). Strict charset + length +
        // shape mirrors `handle_set_secret`.
        validate_vault_key_path(&key_path).map_err(|e| e.extend_safe())?;

        let secrets_manager = ctx.data::<Arc<talos_secrets_manager::SecretsManager>>()?;

        // Get authenticated user_id from context
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

        // delete_secret is a write — Viewer must not be able to delete
        // org-shared secrets. Use role-filtered helper.
        let org_ids: Vec<uuid::Uuid> = crate::schema::user_writable_org_ids(ctx).await?;

        // MCP-872 (2026-05-14): log the underlying error before
        // collapsing to the generic response so a DB outage / cascade
        // FK failure / decryption error is distinguishable from a real
        // not-found-or-access-denied hit on the operator side.
        secrets_manager
            .delete_secret(&key_path, Some(*user_id), &org_ids)
            .await
            .map_err(|e| {
                tracing::error!(
                    key_path = %key_path,
                    error = %e,
                    "delete_secret failed"
                );
                // MCP-964: lowercase 'n' in "not found" + lowercase
                // 'p' in "permission" miss the case-sensitive whitelist.
                async_graphql::Error::new("Secret not found or permission denied").extend_safe()
            })?;
        Ok(true)
    }
}
