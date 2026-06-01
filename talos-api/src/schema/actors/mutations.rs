//! GraphQL Mutation resolvers (MutationRoot).

use async_graphql::{Context, Result, SimpleObject};
// use sha2::Digest; // unused
// use std::sync::Arc; // unused
// use tower_cookies::{Cookie, Cookies}; // unused
use uuid::Uuid;

use crate::schema::types::*;
#[allow(unused_imports)]
use crate::schema::types::*;
use crate::schema::SafeErrorExtensions;
use crate::schema::{require_2fa, require_scope};

#[derive(Default)]
pub struct ActorsMutations;

#[async_graphql::Object]
impl ActorsMutations {
    async fn register_mcp_agent(
        &self,
        ctx: &Context<'_>,
        name: String,
        role_name: String,
    ) -> Result<McpAgentCreated> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;

        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?.clone();

        // MCP-769 (2026-05-13): canonical content discipline matching
        // `create_actor` (lines 135-184 below) and `create_api_key`
        // (security/mutations.rs). Pre-fix the shallow length-only
        // check accepted whitespace-only / control-char / `\0` names
        // that corrupt audit-log summary text and degrade
        // lookup-by-name UX. `register_mcp_agent` is admin-scoped +
        // 2FA-required; its name is the primary operator-facing
        // identifier for MCP agents and lands in `admin_event_log`.
        // MCP-918: every validation message marked .extend_safe() so
        // operators see the actual rejection reason, not "Internal
        // server error" from the production scrubber.
        let trimmed_name = name.trim();
        if trimmed_name.is_empty() {
            return Err(async_graphql::Error::new(
                "Agent name must be 1-100 characters (non-whitespace)",
            )
            .extend_safe());
        }
        if trimmed_name.len() > 100 {
            return Err(
                async_graphql::Error::new("Agent name must be 1-100 characters").extend_safe(),
            );
        }
        talos_validation::reject_control_chars(
            "Agent name",
            &name,
            talos_validation::LineMode::MultiLine,
        )
        .map_err(|e| async_graphql::Error::new(e.message).extend_safe())?;
        let name = trimmed_name.to_string();

        // Look up the role
        //
        // MCP-872 (2026-05-14): log the underlying sqlx error before
        // collapsing to the generic "Database error" response so a
        // connection timeout / query bug / FK violation is
        // distinguishable from a missing-row hit on the operator
        // side. User-facing message stays generic.
        let role_id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM agent_roles WHERE name = $1")
                .bind(&role_name)
                .fetch_optional(&db_pool)
                .await
                .map_err(|e| {
                    tracing::error!(
                        role_name = %role_name,
                        error = %e,
                        "register_mcp_agent: agent_roles lookup failed"
                    );
                    async_graphql::Error::new("Database error").extend_safe()
                })?;

        let role_id = role_id.ok_or_else(|| {
            // MCP-1048: .extend_safe() + bounded_preview on role_name.
            // Pre-fix the lowercase "not found" missed the case-sensitive
            // scrubber whitelist (MCP-964 sibling) and role_name was
            // reflected uncapped (MCP-1030 sibling).
            async_graphql::Error::new(format!(
                "Role '{}' not found. Available roles: System Administrator, Human Resources, DevOps Auto-Remediation, Financial Analyst",
                talos_text_util::bounded_preview(&role_name, 64)
            )).extend_safe()
        })?;

        // Generate a secure random token via OS entropy
        use rand::RngCore;
        let mut token_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token_bytes);
        let token = format!("talos_mcp_{}", hex::encode(token_bytes));

        // Hash for storage (bcrypt) and lookup (SHA-256)
        // MCP-872 (2026-05-14): log spawn_blocking join failures + bcrypt
        // failures distinctly. Both pre-fix paths collapsed to the same
        // opaque "Failed to hash token" with no underlying signal —
        // a panic in the spawn (JoinError) and a bcrypt internal error
        // are very different operator-facing causes.
        let token_clone = token.clone();
        let bcrypt_hash = tokio::task::spawn_blocking(move || bcrypt::hash(&token_clone, 10))
            .await
            .map_err(|e| {
                tracing::error!(
                    error = %e,
                    "register_mcp_agent: bcrypt spawn_blocking JoinError"
                );
                async_graphql::Error::new("Failed to hash token").extend_safe()
            })?
            .map_err(|e| {
                tracing::error!(
                    error = %e,
                    "register_mcp_agent: bcrypt::hash failed"
                );
                async_graphql::Error::new("Failed to hash token").extend_safe()
            })?;

        let lookup_hash = format!(
            "{:x}",
            <sha2::Sha256 as sha2::Digest>::digest(token.as_bytes())
        );

        let agent_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO mcp_agents (id, name, role_id, token_hash, token_lookup_hash, user_id) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(agent_id)
        .bind(&name)
        .bind(role_id)
        .bind(&bcrypt_hash)
        .bind(&lookup_hash)
        .bind(*user_id)
        .execute(&db_pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("mcp_agents_name_key") {
                // MCP-1200 (2026-05-17): .extend_safe() added so the
                // duplicate-name message survives the production
                // scrubber. Pre-fix the Error::new on this line lacked
                // .extend_safe() AND the sibling else-branch on the
                // next call DID have it — the existing lint check 14
                // saw the sibling's .extend_safe() in its 8-line
                // lookahead and treated both as covered (blind spot).
                // The message had no whitelist-substring match either
                // ("already exists" not in the canonical list) so the
                // scrubber replaced it with "Internal server error",
                // leaving operators with no actionable signal.
                async_graphql::Error::new(format!("Agent name '{}' already exists", name))
                    .extend_safe()
            } else {
                tracing::error!("Failed to register MCP agent: {}", e);
                async_graphql::Error::new("Failed to register agent").extend_safe()
            }
        })?;

        tracing::info!(
            agent_id = %agent_id,
            agent_name = %name,
            role = %role_name,
            "MCP agent registered"
        );

        // Write to append-only admin_event_log for WORM-style audit trail.
        talos_actor_repository::spawn_log_admin_event(
            db_pool.clone(),
            *user_id,
            "registered",
            "mcp_agent",
            Some(agent_id),
            format!("MCP agent '{}' registered with role '{}'", name, role_name),
            Some(serde_json::json!({ "agent_id": agent_id, "role": role_name })),
        );

        Ok(McpAgentCreated {
            agent_id,
            name,
            token,
            role: role_name,
        })
    }

    async fn create_actor(
        &self,
        ctx: &Context<'_>,
        input: CreateActorInput,
    ) -> Result<ActorSummary> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let description = input.description;

        // MCP-832 (2026-05-14): MCP-769 sweep — replace shallow length-only
        // check with focused content-discipline via `validate_display_name`.
        // Pre-fix `name: "   "` was rejected by `.trim().is_empty()` but
        // `name: "\0evil"` slipped through; the actor name is rendered
        // in the dashboard and on every spawn_log_action audit row, so
        // a `\0` would corrupt the audit display + UPDATEs (MCP-431).
        // `is_empty() after trim` was already enforced upstream — this
        // adds the control-char rejection that was missing and trims
        // the bound value so the persisted name matches what readers
        // see (MCP-231 parity for actors).
        let trimmed_name = crate::schema::validate_display_name("Actor name", &input.name, 100)
            .map_err(|e| e.extend_safe())?;
        let name = trimmed_name.to_string();
        // MCP-748: mirror MCP `handle_create_actor` content discipline
        // (cap 5000, trim, reject whitespace-only / control chars / `\0`).
        // MCP-837 (2026-05-14): routed through canonical
        // `validate_description_content` so the 4-step shape lives in
        // one place across create_actor / update_actor /
        // publish_workflow_version / create_secret.
        let description = match description {
            None => None,
            Some(d) if d.is_empty() => None,
            Some(d) => Some(
                crate::schema::validate_description_content("description", &d, 5000)
                    .map_err(|e| e.extend_safe())?
                    .to_string(),
            ),
        };

        let max_world = input
            .max_capability_world
            .unwrap_or_else(|| "minimal-node".to_string());
        // MCP-817 (2026-05-14): delegate to canonical
        // `talos_capability_world::is_actor_ceiling_world` instead of
        // the hand-rolled `valid_worlds` array. Pre-fix the array was
        // MISSING `agent-node` AND `llm-node` — operators could not
        // create actors at the agent or llm tier via the GraphQL
        // mutation (the MCP path accepted both after MCP-816). Same
        // GraphQL-mirrors-MCP drift class as MCP-292 ("GraphQL
        // handlers must mirror MCP RBAC checks"). The user_ceiling
        // resolution further down already uses
        // `is_actor_ceiling_world` (MCP-648); this validation block
        // had been authored before that helper landed and never
        // migrated.
        if !talos_capability_world::is_actor_ceiling_world(&max_world) {
            return Err(async_graphql::Error::new(format!(
                "Invalid max_capability_world. Valid values: {}",
                talos_capability_world::actor_ceiling_worlds_csv()
            ))
            .extend_safe());
        }

        let db_pool = ctx.data::<sqlx::PgPool>()?;

        // Human RBAC: the actor's ceiling cannot exceed the calling user's
        // grant. Without this check the GraphQL path bypasses the
        // user_capability_grants ceiling that the MCP create_actor /
        // clone_actor handlers enforce — a user with an `http-node` grant
        // could create an `automation-node` actor and gain every WIT host
        // function via workflows running as that actor.
        //
        // MCP-648 (2026-05-13): route through `is_actor_ceiling_world`
        // for the same drift-elimination reason as the MCP path. The
        // pre-fix match arms were STALE (no `llm-node` despite it being
        // in `ACTOR_CEILING_WORLDS`) and an `llm-node` grant got
        // over-restricted to `http-node`. Recognised worlds pass
        // through; unrecognised values (legacy data, direct SQL writes)
        // collapse to the conservative default rather than silently
        // granting tier-7 via `world_rank`'s unknown-world default.
        let user_ceiling: String = {
            let repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
            match repo
                .get_user_max_capability_world(user_id)
                .await
                .ok()
                .flatten()
            {
                Some(world) if talos_capability_world::is_actor_ceiling_world(&world) => world,
                _ => "http-node".to_string(),
            }
        };
        // Wasm-security review 2026-05-28 (HIGH): partial-order lattice gate
        // (mirrors the MCP `handle_create_actor` fix) — the `world_rank`
        // comparison wrongly admitted lattice-incomparable siblings.
        if !talos_capability_world::ceiling_permits(&user_ceiling, &max_world) {
            return Err(async_graphql::Error::new(format!(
                "Your capability ceiling is '{}'. Creating an actor with '{}' \
                 requires a higher grant — request elevation from a platform admin.",
                user_ceiling, max_world
            ))
            .extend_safe());
        }

        let actor_id = Uuid::new_v4();

        // RFC 0005 S3: INSERT on a per-user scoped tx so the actors RLS
        // policy's WITH CHECK pins the new row to the caller — if the
        // bound user_id ever drifted from the acting user, the insert
        // fails closed (42501) rather than creating a cross-tenant actor.
        // Commit before the post-insert log/summary (they reference the
        // row).
        let mut tx = talos_db::begin_user_scoped(db_pool, user_id)
            .await
            .map_err(|e| async_graphql::Error::new(format!("tenant scope: {e}")).extend_safe())?;
        sqlx::query(
            "INSERT INTO actors (id, user_id, name, description, max_capability_world, status) \
             VALUES ($1, $2, $3, $4, $5, 'active')",
        )
        .bind(actor_id)
        .bind(user_id)
        .bind(&name)
        .bind(&description)
        .bind(&max_world)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create actor: {}", e);
            async_graphql::Error::new("Failed to create actor").extend_safe()
        })?;
        tx.commit()
            .await
            .map_err(|e| async_graphql::Error::new(format!("commit: {e}")).extend_safe())?;

        talos_actor_repository::spawn_log_action(
            db_pool.clone(),
            actor_id,
            "created",
            None,
            None,
            format!("Actor '{}' created from dashboard", name),
            Some(serde_json::json!({ "max_capability_world": max_world })),
        );

        super::helpers::fetch_actor_summary_post_mutation(db_pool, actor_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch created actor: {}", e);
                async_graphql::Error::new("Failed to fetch created actor").extend_safe()
            })
    }

    async fn update_actor_status(
        &self,
        ctx: &Context<'_>,
        id: Uuid,
        status: String,
    ) -> Result<ActorSummary> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        if status != "active" && status != "suspended" {
            return Err(
                async_graphql::Error::new("Invalid status. Use 'active' or 'suspended'")
                    .extend_safe()
                    .extend_safe(),
            );
        }

        let db_pool = ctx.data::<sqlx::PgPool>()?;

        // MCP-647 (2026-05-13): terminal-state guard mirrors the MCP
        // path's MCP-645 fix. The GraphQL mutator had NO guard at all
        // — the handler validated `status in {active, suspended}` and
        // delegated to inline SQL with no `status NOT IN (...)` check,
        // so the dashboard could reactivate an archived/terminated
        // actor at will. Cross-protocol parity matters here: MCP-292
        // family documents that GraphQL handlers must mirror MCP
        // RBAC + state checks. Closing at the SQL layer makes the
        // IRREVERSIBLE contract documented on terminate_actor and
        // archive_actor unconditional.
        // RFC 0005 S3: run the UPDATE on a per-user scoped tx so the
        // actors RLS policy backstops it (USING doubles as WITH CHECK on
        // the update — the row stays owned by the caller).
        let mut tx = talos_db::begin_user_scoped(db_pool, user_id)
            .await
            .map_err(|e| async_graphql::Error::new(format!("tenant scope: {e}")).extend_safe())?;
        let result = sqlx::query(
            "UPDATE actors SET status = $1, updated_at = now() \
             WHERE id = $2 AND user_id = $3 \
             AND status NOT IN ('archived', 'terminated')",
        )
        .bind(&status)
        .bind(id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update actor status: {}", e);
            async_graphql::Error::new("Failed to update actor status").extend_safe()
        })?;
        tx.commit()
            .await
            .map_err(|e| async_graphql::Error::new(format!("commit: {e}")).extend_safe())?;

        if result.rows_affected() == 0 {
            // rows_affected = 0 collapses three cases into one
            // user-facing message:
            //   * actor doesn't exist
            //   * actor exists but is owned by another user
            //   * actor is in a terminal state (archived/terminated)
            // The operator's resolution path is the same for all
            // three — check actor status / ownership, create a new
            // actor if the original is terminal — so a single
            // message is acceptable (and doesn't leak existence
            // information across tenants).
            return Err(async_graphql::Error::new(
                "Actor not found, access denied, or in a terminal state (archived or terminated)",
            )
            .extend_safe());
        }

        talos_actor_repository::spawn_log_action(
            db_pool.clone(),
            id,
            "status_updated",
            None,
            None,
            format!("Actor status set to '{}' from dashboard", status),
            None,
        );

        super::helpers::fetch_actor_summary_post_mutation(db_pool, id, user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch updated actor: {}", e);
                async_graphql::Error::new("Failed to fetch updated actor").extend_safe()
            })
    }

    async fn terminate_actor(
        &self,
        ctx: &Context<'_>,
        id: Uuid,
        cleanup_workflows: Option<bool>,
    ) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let db_pool = ctx.data::<sqlx::PgPool>()?;
        let cleanup = cleanup_workflows.unwrap_or(false);

        // RFC 0005 S3: per-user scoped tx → actors RLS backstops the
        // UPDATE (see update_actor_status).
        let mut tx = talos_db::begin_user_scoped(db_pool, user_id)
            .await
            .map_err(|e| async_graphql::Error::new(format!("tenant scope: {e}")).extend_safe())?;
        let result = sqlx::query(
            "UPDATE actors SET status = 'terminated', updated_at = now() WHERE id = $1 AND user_id = $2",
        )
        .bind(id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("Failed to terminate actor: {}", e);
            async_graphql::Error::new("Failed to terminate actor").extend_safe()
        })?;
        tx.commit()
            .await
            .map_err(|e| async_graphql::Error::new(format!("commit: {e}")).extend_safe())?;

        if result.rows_affected() == 0 {
            return Err(
                async_graphql::Error::new("Actor not found or access denied").extend_safe(),
            );
        }

        // MCP-841 (2026-05-14): distinguish "cleanup ran and 0 workflows
        // matched" from "cleanup attempted but DB hiccupped". Pre-fix
        // `.unwrap_or(None)` collapsed both into `archived_count = 0`
        // and the audit log recorded `archived_workflows: 0` with no
        // signal of failure. Operators looking at the action log for
        // forensics ("how many workflows belonged to this actor?")
        // couldn't distinguish a clean termination of an actor with
        // no workflows from a failed cleanup attempt. Same
        // misleading-discriminator class as MCP-838/839/840 applied
        // to the audit-log surface. Actor termination IS still
        // committed (above) regardless of cleanup outcome — this is
        // best-effort, mutation stays Ok(true) but the trail is honest.
        let mut archived_count = 0i64;
        let mut cleanup_failed = false;
        if cleanup {
            // RFC 0005 S3: scope the best-effort workflow archive on a
            // per-user tx so the workflows RLS policy (USING-as-WITH-CHECK)
            // backstops it — only the caller's own workflows for this actor
            // are archived. begin/commit failures fold into the existing
            // cleanup_failed path (the actor is already terminated above).
            let archive_res: Result<Option<i64>, sqlx::Error> = async {
                let mut tx = talos_db::begin_user_scoped(db_pool, user_id)
                    .await
                    .map_err(|e| sqlx::Error::Protocol(format!("tenant scope: {e}")))?;
                let n = sqlx::query_scalar::<_, i64>(
                    "WITH updated AS (
                        UPDATE workflows SET status = 'archived', updated_at = now()
                        WHERE actor_id = $1 AND (status IS NULL OR status != 'archived')
                        RETURNING 1
                     ) SELECT COUNT(*) FROM updated",
                )
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(n)
            }
            .await;
            match archive_res {
                Ok(n) => archived_count = n.unwrap_or(0),
                Err(e) => {
                    cleanup_failed = true;
                    tracing::warn!(
                        target: "talos_audit",
                        actor_id = %id,
                        error = %e,
                        "terminate_actor: cleanup_workflows archive failed — actor IS terminated but its workflows may still appear active. Retry termination with cleanup_workflows=true once the DB recovers."
                    );
                }
            }
        }

        let mut details = serde_json::json!({ "archived_workflows": archived_count });
        if cleanup_failed {
            // Surface in the audit log so operators reading actor history
            // can distinguish "cleanly archived 0" from "cleanup failed".
            if let Some(obj) = details.as_object_mut() {
                obj.insert("cleanup_failed".into(), serde_json::Value::Bool(true));
            }
        }
        talos_actor_repository::spawn_log_action(
            db_pool.clone(),
            id,
            "terminated",
            None,
            None,
            format!("Actor terminated from dashboard (cleanup={})", cleanup),
            Some(details),
        );

        Ok(true)
    }

    /// Write (upsert) a memory entry for an actor. Returns the saved entry.
    /// Update an actor's name and/or description.
    async fn update_actor(
        &self,
        ctx: &Context<'_>,
        id: Uuid,
        name: Option<String>,
        description: Option<String>,
        #[graphql(desc = "New capability ceiling world. Must be one of the valid world names.")]
        max_capability_world: Option<String>,
    ) -> Result<ActorSummary> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        if name.is_none() && description.is_none() && max_capability_world.is_none() {
            return Err(async_graphql::Error::new(
                "Provide at least one of: name, description, max_capability_world",
            )
            .extend_safe());
        }

        // MCP-748: mirror MCP `handle_update_actor` (cap 5000 + trim +
        // whitespace-only/control-char reject). Empty-string semantics
        // differ from create_actor: `Some("")` here EXPLICITLY clears
        // the column (operator path: "set this to empty" → SQL UPDATE
        // binds empty), whereas create_actor maps `Some("")` to None
        // (operator omitted the field — there's no row to clear).
        // MCP-837 (2026-05-14): canonical helper for content validation;
        // empty-string handling stays here because semantics diverge.
        let description = match description {
            None => None,
            Some(d) if d.is_empty() => Some(String::new()), // empty string clears
            Some(d) => Some(
                crate::schema::validate_description_content("description", &d, 5000)
                    .map_err(|e| e.extend_safe())?
                    .to_string(),
            ),
        };

        // MCP-832 (2026-05-14): MCP-769 sweep — same content-discipline
        // upgrade as `create_actor`. Pre-fix the inline check only
        // tested `trim().is_empty()` and length; control-chars / `\0`
        // slipped through. Use the canonical helper for the create/update
        // sibling parity.
        let name: Option<String> = match name {
            Some(ref n) => {
                let trimmed = crate::schema::validate_display_name("Actor name", n, 100)
                    .map_err(|e| e.extend_safe())?;
                Some(trimmed.to_string())
            }
            None => None,
        };

        // Validate against canonical ACTOR_CEILING_WORLDS (talos-capability-world).
        // The previous inline list was missing `llm-node` — drift between
        // GraphQL and MCP would silently let users with an llm-node grant
        // fail to create actors at their ceiling via this surface.
        if let Some(ref w) = max_capability_world {
            if !talos_capability_world::is_actor_ceiling_world(w) {
                return Err(async_graphql::Error::new(format!(
                    "Invalid max_capability_world. Valid values: {}",
                    talos_capability_world::actor_ceiling_worlds_csv()
                ))
                .extend_safe());
            }
        }

        let db_pool = ctx.data::<sqlx::PgPool>()?;

        // Human RBAC: enforce the user's capability-grant ceiling on
        // ceiling raises. Same gate as create_actor; without it a user
        // can grant their own actor an arbitrary world via the dashboard,
        // bypassing the user_capability_grants ceiling that MCP enforces.
        // MCP-648: same `is_actor_ceiling_world` consolidation as
        // create_actor above.
        if let Some(ref w) = max_capability_world {
            let user_ceiling: String = {
                let repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
                match repo
                    .get_user_max_capability_world(user_id)
                    .await
                    .ok()
                    .flatten()
                {
                    Some(world) if talos_capability_world::is_actor_ceiling_world(&world) => world,
                    _ => "http-node".to_string(),
                }
            };
            // Wasm-security review 2026-05-28 (HIGH): partial-order lattice gate.
            if !talos_capability_world::ceiling_permits(&user_ceiling, w.as_str()) {
                return Err(async_graphql::Error::new(format!(
                    "Your capability ceiling is '{}'. Updating an actor to '{}' \
                     requires a higher grant — request elevation from a platform admin.",
                    user_ceiling, w
                ))
                .extend_safe());
            }
        }

        let mut set_parts: Vec<String> = vec!["updated_at = NOW()".to_string()];
        let mut param_count = 0usize;
        if name.is_some() {
            param_count += 1;
            set_parts.push(format!("name = ${}", param_count));
        }
        if description.is_some() {
            param_count += 1;
            set_parts.push(format!("description = ${}", param_count));
        }
        if max_capability_world.is_some() {
            param_count += 1;
            set_parts.push(format!("max_capability_world = ${}", param_count));
        }
        let sql = format!(
            "UPDATE actors SET {} WHERE id = ${} AND user_id = ${}",
            set_parts.join(", "),
            param_count + 1,
            param_count + 2,
        );

        // RFC 0005 S3: per-user scoped tx → actors RLS backstops the
        // UPDATE (see update_actor_status).
        let mut tx = talos_db::begin_user_scoped(db_pool, user_id)
            .await
            .map_err(|e| async_graphql::Error::new(format!("tenant scope: {e}")).extend_safe())?;
        let mut q = sqlx::query(&sql);
        if let Some(ref n) = name {
            q = q.bind(n.trim());
        }
        if let Some(ref d) = description {
            q = q.bind(d.as_str());
        }
        if let Some(ref w) = max_capability_world {
            q = q.bind(w.as_str());
        }
        let result = q
            .bind(id)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                if e.to_string().contains("unique") || e.to_string().contains("duplicate") {
                    async_graphql::Error::new(format!(
                        "An actor named '{}' already exists",
                        name.as_deref().unwrap_or("")
                    ))
                    .extend_safe()
                } else {
                    tracing::error!("update_actor failed: {}", e);
                    async_graphql::Error::new("Failed to update actor").extend_safe()
                }
            })?;
        tx.commit()
            .await
            .map_err(|e| async_graphql::Error::new(format!("commit: {e}")).extend_safe())?;

        if result.rows_affected() == 0 {
            return Err(
                async_graphql::Error::new("Actor not found or access denied").extend_safe(),
            );
        }

        let update_summary = {
            let mut parts = vec![];
            if name.is_some() {
                parts.push("name");
            }
            if description.is_some() {
                parts.push("description");
            }
            if max_capability_world.is_some() {
                parts.push("capability world");
            }
            format!("Actor {} updated from dashboard", parts.join(", "))
        };
        talos_actor_repository::spawn_log_action(
            db_pool.clone(),
            id,
            "updated",
            None,
            None,
            update_summary,
            max_capability_world
                .as_ref()
                .map(|w| serde_json::json!({ "max_capability_world": w })),
        );

        super::helpers::fetch_actor_summary_post_mutation(db_pool, id, user_id)
            .await
            .map_err(|e: sqlx::Error| e.extend_safe())
    }

    async fn write_actor_memory(
        &self,
        ctx: &Context<'_>,
        input: WriteActorMemoryInput,
    ) -> Result<ActorMemoryEntry> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data::<sqlx::PgPool>()?;

        // Validate actor ownership — RFC 0005 S3: on a per-user scoped tx
        // so the actors RLS policy backstops the check (the memory write
        // itself goes through talos_memory).
        let mut tx = talos_db::begin_user_scoped(db_pool, user_id)
            .await
            .map_err(|e| async_graphql::Error::new(format!("tenant scope: {e}")).extend_safe())?;
        let owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM actors WHERE id = $1 AND user_id = $2 AND status != 'terminated')",
        )
        .bind(input.actor_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| e.extend_safe())?;
        tx.commit()
            .await
            .map_err(|e| async_graphql::Error::new(format!("commit: {e}")).extend_safe())?;

        if !owned {
            return Err(
                async_graphql::Error::new("Actor not found or access denied").extend_safe(),
            );
        }

        // MCP-834 (2026-05-14): delegate to canonical
        // `talos_memory::validate_memory_key` (mirrors MCP-388 trim +
        // whitespace-only + len ≤ 500 + control-char rejection). Pre-fix
        // GraphQL capped at 200 (vs MCP's 500 → asymmetric — keys that
        // MCP accepted couldn't be re-written via GraphQL), allowed
        // whitespace-only (`"   "` slipped through and persisted as a
        // key no recall could match), and accepted control chars / `\0`
        // (downstream UPDATE-by-key crashes opaquely, MCP-431). Trim
        // the key at the boundary so the persisted key matches what
        // recall paths see (the MCP-231 / MCP-388 trim invariant).
        let trimmed_key = talos_memory::validate_memory_key(&input.key)
            .map_err(|msg| async_graphql::Error::new(msg).extend_safe())?;
        let key = trimmed_key.to_string();
        // MCP-869 (2026-05-14): pre-parse size cap on `input.value` to
        // bound the JSON-parser allocation. Without it a caller could
        // submit a multi-MB string; serde_json::from_str would allocate
        // the full Value tree proportional to that, and only AFTER the
        // re-serialization in `talos_memory::persist_memory` would the
        // canonical 64-KiB MAX_VALUE_BYTES cap fire — so the parser
        // burn is wasted controller work on a write that's destined to
        // fail. Cap at 4× MAX_VALUE_BYTES (256 KiB) so pretty-printed
        // JSON with generous whitespace still parses; anything bigger
        // is comfortably above the legitimate payload envelope and
        // gets rejected before allocation. Same pre-parse-cap shape as
        // MCP-666 / MCP-868.
        const MEMORY_VALUE_INPUT_MAX_BYTES: usize = 4 * talos_memory::MAX_VALUE_BYTES;
        if input.value.len() > MEMORY_VALUE_INPUT_MAX_BYTES {
            return Err(async_graphql::Error::new(format!(
                "value must be ≤ {} bytes when serialised (got {})",
                MEMORY_VALUE_INPUT_MAX_BYTES,
                input.value.len()
            ))
            .extend_safe());
        }
        let value: serde_json::Value = serde_json::from_str(&input.value)
            .map_err(|_| async_graphql::Error::new("value must be valid JSON").extend_safe())?;

        let memory_type = input.memory_type.as_deref().unwrap_or("working");

        // MCP-821 (2026-05-14): switch from hardcoded error-message list
        // to canonical `talos_memory::memory_types_csv()`. Same
        // canonicalization sweep as MCP-819 (which closed 6 sites in
        // talos-mcp-handlers/actor.rs); the GraphQL persist_memory
        // mutation was the lone unswept reference in talos-api. A new
        // memory_type added to `MEMORY_TYPES` would have silently left
        // this error message stale.
        if !talos_memory::is_valid_memory_type(memory_type) {
            return Err(async_graphql::Error::new(format!(
                "memory_type must be one of: {}",
                talos_memory::memory_types_csv()
            ))
            .extend_safe());
        }

        // Delegate to the canonical write path — includes embedding
        // computation + graph-RAG entity extraction. Writes made
        // directly against the table bypassed both and caused
        // semantic recall misses.
        talos_actor_memory_service::persist_memory(
            db_pool,
            input.actor_id,
            &key, // MCP-834: trimmed at the boundary
            &value,
            memory_type,
            input.ttl_hours,
        )
        .await
        .map_err(|e| {
            tracing::error!("write_actor_memory failed: {}", e);
            async_graphql::Error::new("Failed to write memory").extend_safe()
        })?;

        // Re-fetch the canonical stored row so the GraphQL response
        // reflects the computed expires_at / updated_at exactly.
        let row = talos_actor_memory_service::recall_exact(db_pool, input.actor_id, &key)
            .await
            .map_err(|e| {
                tracing::error!("write_actor_memory post-read failed: {}", e);
                async_graphql::Error::new("Failed to read memory back").extend_safe()
            })?
            .ok_or_else(|| async_graphql::Error::new("Memory was not persisted").extend_safe())?;

        Ok(ActorMemoryEntry {
            key: row.key,
            value: row.value.to_string(),
            memory_type: row.memory_type,
            expires_at: row.expires_at.map(|d| d.to_rfc3339()),
            updated_at: row.updated_at.to_rfc3339(),
        })
    }

    /// Delete a memory entry by key for an actor the current user owns.
    async fn delete_actor_memory(
        &self,
        ctx: &Context<'_>,
        actor_id: Uuid,
        key: String,
    ) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data::<sqlx::PgPool>()?;

        // MCP-834 (2026-05-14): mirror MCP `handle_actor_forget` MCP-388
        // — trim the lookup key so a `key: "  foo  "` request from a
        // paste-cleaned editor matches what `write_actor_memory`
        // persisted. Without trim parity, delete silently no-ops on
        // keys the operator can SEE in `list_actor_memories`.
        // Sibling of write_actor_memory above; same canonical helper.
        let trimmed_key = talos_memory::validate_memory_key(&key)
            .map_err(|msg| async_graphql::Error::new(msg).extend_safe())?;

        // Verify ownership before deleting — RFC 0005 S3: per-user scoped
        // tx so the actors RLS policy backstops the check.
        let mut tx = talos_db::begin_user_scoped(db_pool, user_id)
            .await
            .map_err(|e| async_graphql::Error::new(format!("tenant scope: {e}")).extend_safe())?;
        let owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM actors WHERE id = $1 AND user_id = $2)",
        )
        .bind(actor_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| e.extend_safe())?;
        tx.commit()
            .await
            .map_err(|e| async_graphql::Error::new(format!("commit: {e}")).extend_safe())?;

        if !owned {
            return Err(
                async_graphql::Error::new("Actor not found or access denied").extend_safe(),
            );
        }

        let deleted = talos_memory::forget_exact(db_pool, actor_id, trimmed_key)
            .await
            .map_err(|e| {
                tracing::error!("delete_actor_memory failed: {}", e);
                async_graphql::Error::new("Failed to delete memory").extend_safe()
            })?;

        Ok(deleted > 0)
    }

    /// Clone an actor, copying its semantic and episodic memories into the new actor.
    async fn clone_actor(
        &self,
        ctx: &Context<'_>,
        id: Uuid,
        #[graphql(desc = "Name for the cloned actor. Defaults to 'Copy of <original name>'.")]
        name: Option<String>,
    ) -> Result<ActorSummary> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::WorkflowsWrite)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .copied()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

        let db_pool = ctx.data::<sqlx::PgPool>()?;
        use sqlx::Row as _;

        // RFC 0005 S3: the source-actor ownership read + the clone INSERT
        // share one per-user scoped tx — the actors RLS policy backstops
        // both, and its WITH CHECK pins the new row to the caller. Commit
        // before the memory copy below (it needs the new actor row).
        let mut tx = talos_db::begin_user_scoped(db_pool, user_id)
            .await
            .map_err(|e| async_graphql::Error::new(format!("tenant scope: {e}")).extend_safe())?;

        // Fetch source actor (ownership check)
        let src = sqlx::query(
            "SELECT name, description, max_capability_world FROM actors \
             WHERE id = $1 AND user_id = $2 AND status != 'terminated'",
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| e.extend_safe())?
        .ok_or_else(|| {
            async_graphql::Error::new("Actor not found or access denied").extend_safe()
        })?;

        let src_name: String = src.get("name");
        let src_description: Option<String> = src.get("description");
        let src_world: Option<String> = src.get("max_capability_world");

        let clone_name = name
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| format!("Copy of {}", src_name));
        if clone_name.len() > 100 {
            return Err(async_graphql::Error::new("name must be ≤100 characters").extend_safe());
        }

        let new_id = uuid::Uuid::new_v4();
        let world = src_world.as_deref().unwrap_or("minimal-node");

        sqlx::query(
            "INSERT INTO actors (id, user_id, name, description, max_capability_world, status) \
             VALUES ($1, $2, $3, $4, $5, 'active')",
        )
        .bind(new_id)
        .bind(user_id)
        .bind(&clone_name)
        .bind(&src_description)
        .bind(world)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("clone_actor insert failed: {}", e);
            async_graphql::Error::new("Failed to clone actor").extend_safe()
        })?;
        tx.commit()
            .await
            .map_err(|e| async_graphql::Error::new(format!("commit: {e}")).extend_safe())?;

        // Copy semantic (permanent) and episodic (fresh 7-day TTL) memories
        // through the canonical talos_memory entry point — same DEK lineage
        // (per-user) so ciphertext passthrough is safe and avoids a per-row
        // decrypt/re-encrypt round-trip. Failures are logged but not fatal:
        // the actor itself was already inserted above and the response
        // includes `memories_copied=0` so the caller can detect partial
        // success. (Pre-Phase-B regression class: silent SQL errors here
        // were invisible without controller logs — the explicit warn closes
        // that gap.)
        // MCP-654: route through the SQL-gated wrapper instead of
        // calling `talos_memory::clone_memories` directly. The wrapper
        // re-verifies that BOTH actors belong to `user_id` in a single
        // SELECT, defense-in-depth on top of the source-actor ownership
        // check at the top of this handler. Mirrors the MCP-side
        // `handle_clone_actor` path (`state.actor_repo.clone_actor_memories(...)`)
        // — same cross-protocol parity class as MCP-647/648/649/650/651/652.
        // Without this, a future refactor that decouples the
        // source-actor-ownership probe from the actual call could let a
        // ciphertext-passthrough cross-user clone slip through; the DEK
        // lineage is per-user and the wrapper fails closed on mismatch.
        let actor_repo_for_clone = talos_actor_repository::ActorRepository::new(db_pool.clone());
        let memories_copied: i64 = match actor_repo_for_clone
            .clone_actor_memories(user_id, new_id, id)
            .await
        {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(
                    source_actor_id = %id,
                    target_actor_id = %new_id,
                    error = %e,
                    "clone_actor (gql): bulk memory copy failed"
                );
                0
            }
        };

        // The bulk copy skips embedding — trigger a targeted backfill
        // so cloned memories are immediately searchable.
        if memories_copied > 0 {
            let pool = db_pool.clone();
            tokio::spawn(async move {
                if let Err(e) = talos_actor_memory_service::backfill_embeddings_for_actor(
                    &pool,
                    new_id,
                    memories_copied.min(10_000),
                )
                .await
                {
                    tracing::warn!(
                        actor_id = %new_id,
                        error = %e,
                        "clone_actor (gql): post-clone backfill failed"
                    );
                }
            });
        }

        talos_actor_repository::spawn_log_action(
            db_pool.clone(),
            new_id,
            "created",
            None,
            None,
            format!(
                "Actor cloned from '{}' ({} memories copied) via dashboard",
                src_name, memories_copied
            ),
            Some(serde_json::json!({ "cloned_from": id, "memories_copied": memories_copied })),
        );
        talos_actor_repository::spawn_log_action(
            db_pool.clone(),
            id,
            "cloned",
            None,
            None,
            format!("Actor cloned as '{}' via dashboard", clone_name),
            Some(serde_json::json!({ "clone_id": new_id })),
        );

        super::helpers::fetch_actor_summary_post_mutation(db_pool, new_id, user_id)
            .await
            .map_err(|e: sqlx::Error| e.extend_safe())
    }

    async fn revoke_mcp_agent(&self, ctx: &Context<'_>, id: Uuid) -> Result<bool> {
        require_2fa(ctx)?;
        require_scope(ctx, talos_api_keys::ApiKeyScope::Admin)?;
        let user_id = ctx
            .data_opt::<Uuid>()
            .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;
        let db_pool = ctx.data_unchecked::<sqlx::PgPool>();

        let result = sqlx::query!(
            "DELETE FROM mcp_agents WHERE id = $1 AND user_id = $2",
            id,
            user_id
        )
        .execute(db_pool)
        .await
        .map_err(|e| e.extend_safe())?;

        if result.rows_affected() == 0 {
            return Err(
                async_graphql::Error::new("Agent not found or access denied").extend_safe(),
            );
        }

        Ok(true)
    }
}

#[derive(SimpleObject)]
struct McpAgentCreated {
    agent_id: Uuid,
    name: String,
    token: String,
    role: String,
}
