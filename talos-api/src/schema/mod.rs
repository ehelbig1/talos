//! GraphQL schema definition and shared helpers.
//!
//! The implementation is split across sub-modules for maintainability:
//! - `types` — GraphQL type definitions, input types, enums, DataLoaders
//! - `queries` — Query resolvers (QueryRoot)
//! - `mutations` — Mutation resolvers (MutationRoot)
//! - `subscriptions` — Subscription resolvers (SubscriptionRoot)

pub mod actors;
pub mod auth;
pub mod executions;
pub mod ml;
pub mod modules;
pub mod organizations;
pub mod platform;
pub mod secrets;
pub mod security;
pub mod webhooks;
pub mod workflows;

mod mutations;
mod queries;
mod subscriptions;
pub mod types;

// Re-export everything for backwards compatibility
pub use mutations::MutationRoot;
pub use queries::QueryRoot;
pub use subscriptions::SubscriptionRoot;
pub use types::*;

use async_graphql::{Context, ErrorExtensions, Result};
use uuid::Uuid;

use talos_workflow_engine::ParallelWorkflowEngine;

pub struct ApiKeyScopes(pub Vec<talos_api_keys::ApiKeyScope>);
pub struct IsTwoFactorVerified(pub bool);

/// When present in the GraphQL context, indicates the API key is scoped
/// to a specific organization. Resolvers should restrict resource access
/// to only resources within this org (or owned by the user directly).
pub struct ApiKeyOrgScope(pub Uuid);

/// Marker struct to indicate an error is safe to expose in production.
pub struct SafeError;

pub trait SafeErrorExtensions {
    fn extend_safe(self) -> async_graphql::Error;
}

impl SafeErrorExtensions for async_graphql::Error {
    fn extend_safe(self) -> async_graphql::Error {
        self.extend_with(|_, e| e.set("safe", true))
    }
}

impl SafeErrorExtensions for sqlx::Error {
    fn extend_safe(self) -> async_graphql::Error {
        tracing::error!(error = %self, "Database operation failed");
        async_graphql::Error::new("Database operation failed").extend_safe()
    }
}

pub fn is_safe_error(error: &async_graphql::ServerError) -> bool {
    error
        .extensions
        .as_ref()
        .and_then(|ext| ext.get("safe"))
        .map(|val| matches!(val, async_graphql::Value::Boolean(true)))
        .unwrap_or(false)
}

/// MCP-1051 (2026-05-15): canonical scrubber whitelist substrings.
///
/// The production GraphQL response scrubber (controller/src/main.rs)
/// passes any error message containing one of these substrings through
/// verbatim, even without an explicit `.extend_safe()` marker. This
/// substring fallback is the legacy compatibility layer for paths that
/// haven't migrated to `.extend_safe()`; new code MUST use the explicit
/// marker (lint check 14 enforces it).
///
/// Pre-fix the substring list was duplicated between the scrubber and
/// `scripts/lint-structural.sh::check 14`. Same N-inline-copies drift
/// class as MCP-1037/1038/1040/1041/1049/1050. Hoisting to a Rust
/// `const &[&str]` makes the scrubber + the `is_safe_error_substring`
/// helper share ONE source of truth; the lint still hardcodes the
/// substrings but documents this const as the parity reference.
///
/// **Case-sensitive by design.** MCP-964 found that lowercase "not
/// found" / "invalid" miss the whitelist; the fix was to add
/// `.extend_safe()` at affected sites, not relax the whitelist. This
/// forces error messages to use proper user-facing prose ("Not found"
/// rather than lowercase machine-style "not found").
pub const SAFE_ERROR_SUBSTRINGS: &[&str] = &[
    "Authentication",
    "Access denied",
    "Not found",
    "Invalid",
    "Validation",
    "Unauthorized",
];

/// Returns `true` when `msg` contains any of the [`SAFE_ERROR_SUBSTRINGS`].
/// The production scrubber uses this as the legacy-path fallback when
/// the explicit `extensions.safe = true` marker (set by
/// `.extend_safe()`) is absent.
pub fn is_safe_error_substring(msg: &str) -> bool {
    SAFE_ERROR_SUBSTRINGS
        .iter()
        .any(|substr| msg.contains(substr))
}

pub fn require_scope(ctx: &Context<'_>, required_scope: talos_api_keys::ApiKeyScope) -> Result<()> {
    if let Ok(scopes) = ctx.data::<ApiKeyScopes>() {
        if !scopes.0.contains(&required_scope)
            && !scopes.0.contains(&talos_api_keys::ApiKeyScope::Admin)
        {
            return Err(
                async_graphql::Error::new("Insufficient API key permissions").extend_safe(),
            );
        }
        return Ok(());
    }

    if ctx.data_opt::<Uuid>().is_none() {
        return Err(async_graphql::Error::new(
            "Authentication required: neither API key nor user session found",
        )
        .extend_safe());
    }

    Ok(())
}

pub fn require_2fa(ctx: &Context<'_>) -> Result<()> {
    // MCP-616 (2026-05-12): fail closed when `IsTwoFactorVerified` data is
    // missing entirely. Pre-fix: `if let Ok(verified) = ctx.data::<...>` —
    // if the data wasn't injected, the conditional was skipped and the
    // function returned `Ok(())` (PASS). In current code every auth path
    // injects `IsTwoFactorVerified` alongside `user_id` (JWT: claims-driven;
    // API key: hard-coded `true`), so the fail-open never fires in
    // practice. The fragility is the concern: a future auth path that
    // injects user_id WITHOUT IsTwoFactorVerified (e.g. a new session-
    // cookie variant, MCP-style API token, OAuth flow that splits the
    // two) would silently bypass every 2FA-gated mutation. Make the
    // helper itself fail closed so that defect is impossible. Mutations
    // that should NOT require 2FA (none today, by policy) explicitly
    // skip calling `require_2fa` rather than relying on data absence.
    // The two arms fail closed identically but deserve DIFFERENT messages
    // (2026-07-06). `IsTwoFactorVerified` is injected only when
    // authentication SUCCEEDS (API key or valid JWT — see the /graphql
    // handler in controller main.rs), so the missing-data arm fires for
    // every unauthenticated request — most commonly an EXPIRED session
    // driven from curl/scripts, which don't run the frontend's token
    // refresh. Pre-fix both arms said "Two-Factor Authentication
    // required", sending expired-session users hunting for a 2FA problem
    // that doesn't exist. The missing arm now names the real condition
    // and signposts API keys (the intended lane for non-browser clients);
    // the `!verified` arm keeps the genuine pre-2FA message.
    let verified = ctx.data::<IsTwoFactorVerified>().map_err(|_| {
        async_graphql::Error::new(
            "Authentication required — no valid session or API key on this request \
             (your session may have expired). Log in again, or use an API key \
             (X-API-Key header) for scripts and long-lived clients.",
        )
        .extend_safe()
    })?;
    if !verified.0 {
        return Err(async_graphql::Error::new(
            "Two-Factor Authentication required. Please verify your identity.",
        )
        .extend_safe());
    }
    Ok(())
}

/// Root fields a pre-2FA (password-verified but TOTP-pending) session may
/// invoke. Everything else is refused at the GraphQL entry point — the
/// read-surface counterpart to `require_2fa` on mutations and the REST
/// middleware's blanket pre-2FA 403 (security review 2026-07-19, P3).
///
/// Before this gate, `require_scope` (the query-side authorization helper)
/// checked only that a `user_id` was present, never `IsTwoFactorVerified`,
/// so a session holding the password but not the TOTP could read the entire
/// query surface (workflows, executions, decrypted agent memory via
/// `actorMemories`, secret metadata). Mutations were already blocked by
/// `require_2fa`; REST already returned 403 for pre-2FA tokens. This closes
/// the GraphQL read surface to match.
///
/// `me` is included because it is the ONLY resolver the 2FA login flow needs
/// before verification — it reports the user's 2FA state and is deliberately
/// un-gated (checks `user_id` presence only). The rest are the auth-bootstrap
/// mutations (`login`/`signup`/`verifyTwoFactor`/`refreshToken`/`logout`) plus
/// the introspection meta-fields used by tooling.
pub const PRE_2FA_ALLOWED_ROOT_FIELDS: &[&str] = &[
    "me",
    "verifyTwoFactor",
    "login",
    "signup",
    "refreshToken",
    "logout",
    "__typename",
    "__schema",
    "__type",
];

/// Returns `true` if a pre-2FA session may run the selected operation —
/// i.e. every root field it selects is in [`PRE_2FA_ALLOWED_ROOT_FIELDS`].
///
/// Fails CLOSED: an unparseable query, an unresolved/ambiguous operation
/// name, or an unresolvable (or cyclic) root fragment spread all return
/// `false`. Root-level inline fragments and fragment spreads are resolved so
/// the allowlist can't be evaded by wrapping a disallowed field in a
/// fragment. Pure + unit-tested; the caller (`graphql_handler`) only invokes
/// it for authenticated-but-not-2FA-verified sessions.
pub fn pre_2fa_operation_allowed(query: &str, operation_name: Option<&str>) -> bool {
    use async_graphql::parser::types::{DocumentOperations, OperationDefinition};

    let doc = match async_graphql::parser::parse_query(query) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let op: &OperationDefinition = match &doc.operations {
        DocumentOperations::Single(op) => &op.node,
        DocumentOperations::Multiple(ops) => match operation_name {
            Some(name) => match ops.get(name) {
                Some(op) => &op.node,
                None => return false,
            },
            // Spec requires an operationName when multiple operations are
            // present; tolerate the single-operation-map case, block otherwise.
            None if ops.len() == 1 => &ops.values().next().expect("len==1").node,
            None => return false,
        },
    };
    let mut visiting = std::collections::HashSet::new();
    selection_set_root_fields_allowed(&op.selection_set.node, &doc, &mut visiting)
}

fn selection_set_root_fields_allowed(
    sel: &async_graphql::parser::types::SelectionSet,
    doc: &async_graphql::parser::types::ExecutableDocument,
    visiting: &mut std::collections::HashSet<String>,
) -> bool {
    use async_graphql::parser::types::Selection;
    for item in &sel.items {
        match &item.node {
            Selection::Field(f) => {
                if !PRE_2FA_ALLOWED_ROOT_FIELDS.contains(&f.node.name.node.as_str()) {
                    return false;
                }
            }
            Selection::InlineFragment(inline) => {
                if !selection_set_root_fields_allowed(
                    &inline.node.selection_set.node,
                    doc,
                    visiting,
                ) {
                    return false;
                }
            }
            Selection::FragmentSpread(spread) => {
                let frag_name = spread.node.fragment_name.node.as_str();
                if !visiting.insert(frag_name.to_string()) {
                    // Cyclic fragment — fail closed.
                    return false;
                }
                let allowed = match doc.fragments.get(frag_name) {
                    Some(frag) => selection_set_root_fields_allowed(
                        &frag.node.selection_set.node,
                        doc,
                        visiting,
                    ),
                    None => false,
                };
                visiting.remove(frag_name);
                if !allowed {
                    return false;
                }
            }
        }
    }
    true
}

/// Gate for system-wide / cross-tenant operations.
///
/// `require_scope(Admin)` deliberately session-bypasses (sessions are
/// trusted within their own user scope), which is correct for per-user
/// admin operations like API-key management. But system-wide actions —
/// rotating the master key, the system DEK, re-encrypting all secrets,
/// subscribing to the global DLQ stream — touch every tenant in the
/// deployment and need a stronger gate.
///
/// We treat any user who is `owner` or `admin` of at least one
/// organization as a platform admin. This mirrors the inline check
/// added in r268 for the DLQ subscription. Single-tenant deployments
/// will have exactly one owner who passes; multi-tenant deployments
/// require operators to be explicitly added as org owner/admin before
/// they can run cross-tenant ops.
///
/// Use in addition to `require_2fa` and (where appropriate) the
/// per-user `require_scope` check.
pub async fn require_platform_admin(ctx: &Context<'_>) -> Result<()> {
    let user_id = ctx
        .data_opt::<Uuid>()
        .copied()
        .ok_or_else(|| async_graphql::Error::new("Authentication required").extend_safe())?;

    let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;

    // M T6-1: delegate to the canonical helper so the column source
    // (post-migration `users.is_platform_admin`) is in one place.
    // Pre-fix this inlined the same `EXISTS(SELECT 1 FROM
    // organization_members ...)` SQL the actor-repository helper
    // had — drift risk + the conflation bug fixed in the migration.
    let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
    let is_admin = actor_repo.is_platform_admin(user_id).await.map_err(|e| {
        tracing::error!("require_platform_admin db check failed: {}", e);
        async_graphql::Error::new("Database error").extend_safe()
    })?;

    if !is_admin {
        return Err(
            async_graphql::Error::new("Only platform admins can perform this operation")
                .extend_safe(),
        );
    }

    Ok(())
}

/// Fetch all organization IDs the user belongs to (any role).
///
/// Used by list queries to include org-owned resources alongside personally
/// owned ones: `WHERE user_id = $1 OR org_id = ANY($2)`.
///
/// When the request uses an org-scoped API key (`ApiKeyOrgScope`), the result
/// is restricted to that single org — even if the user belongs to other orgs.
pub async fn user_accessible_org_ids(ctx: &Context<'_>) -> Result<Vec<Uuid>> {
    // If API key is org-scoped, restrict to that org only
    if let Ok(org_scope) = ctx.data::<ApiKeyOrgScope>() {
        return Ok(vec![org_scope.0]);
    }

    // Fast path: if already computed for this request, return cached value.
    if let Ok(cached) = ctx.data::<UserOrgIds>() {
        return Ok(cached.0.clone());
    }

    let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;
    let user_id = ctx
        .data_opt::<Uuid>()
        .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

    // MCP-617 (2026-05-12): sibling fix to MCP-614 — read-path used the
    // same `.unwrap_or_default()` shape that silently produced an empty
    // org list on DB error. For a reader this is also fail-closed (user
    // sees no org-shared resources) but loses the regression signal.
    // Logging at error! level pairs the read+write paths so an
    // `organization_members` schema break surfaces uniformly.
    let org_ids: Vec<Uuid> = match talos_organizations::OrganizationService::list_user_org_ids(
        db_pool, *user_id,
    )
    .await
    {
        Ok(ids) => ids,
        Err(e) => {
            tracing::error!(
                user_id = %user_id,
                error = %e,
                "user_accessible_org_ids: DB query failed — falling back to empty (reader denied)"
            );
            Vec::new()
        }
    };

    Ok(org_ids)
}

/// Fetch organization IDs the user belongs to with **at least Member role**.
///
/// Use this for write paths (update/delete on org-shared resources). The
/// plain `user_accessible_org_ids` returns every org the user belongs to
/// regardless of role — which is correct for reads (Viewer can see) but
/// would let a Viewer update or delete org-shared resources.
///
/// Org-scoped API keys still get a single-org result; if that org's role
/// (looked up here) is Viewer, the result is empty — meaning the API key
/// can read org-shared resources but not write them.
pub async fn user_writable_org_ids(ctx: &Context<'_>) -> Result<Vec<Uuid>> {
    let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;
    let user_id = ctx
        .data_opt::<Uuid>()
        .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

    // Filter by role at the DB layer so a Viewer's org_ids are excluded
    // entirely from write predicates. Member, Admin, Owner all pass.
    //
    // MCP-614 (2026-05-12): log on DB error before falling back to empty.
    // Fail-closed (writer denied on outage) is correct security posture,
    // but `unwrap_or_default()` alone silently hides DB regressions —
    // an `organization_members` schema break (cf. MCP-595/596 column-
    // naming class) would make EVERY write to org-shared resources
    // silently 403 with no operator-facing signal. Logging at error!
    // level surfaces the actual cause so the regression is investigable.
    let mut org_ids: Vec<Uuid> =
        match talos_organizations::OrganizationService::list_user_writable_org_ids(
            db_pool, *user_id,
        )
        .await
        {
            Ok(ids) => ids,
            Err(e) => {
                tracing::error!(
                    user_id = %user_id,
                    error = %e,
                    "user_writable_org_ids: DB query failed — falling back to empty (writer denied)"
                );
                Vec::new()
            }
        };

    // If API key is org-scoped, intersect with that single org so the
    // key can't escape its scope by piggybacking on the user's other
    // memberships.
    if let Ok(org_scope) = ctx.data::<ApiKeyOrgScope>() {
        org_ids.retain(|id| *id == org_scope.0);
    }

    Ok(org_ids)
}

/// Cached org IDs for the current request.
pub struct UserOrgIds(pub Vec<Uuid>);

/// Returns `true` if the current request is restricted to a specific org (org-scoped API key).
/// When true, queries should NOT include personal (user_id-owned) resources.
pub fn is_org_scoped(ctx: &Context<'_>) -> bool {
    ctx.data::<ApiKeyOrgScope>().is_ok()
}

/// Verify that the authenticated user can access a resource (owns it or has org access).
/// For mutations, pass `write = true` to require Member+ role; for reads, Viewer suffices.
pub async fn check_resource_access(
    ctx: &Context<'_>,
    resource_user_id: Uuid,
    resource_org_id: Option<Uuid>,
    write: bool,
) -> Result<()> {
    let db_pool = ctx.data::<sqlx::Pool<sqlx::Postgres>>()?;
    let user_id = ctx
        .data_opt::<Uuid>()
        .ok_or_else(|| async_graphql::Error::new("Authentication required"))?;

    let min_role = if write {
        talos_organizations::OrgRole::Member
    } else {
        talos_organizations::OrgRole::Viewer
    };

    if !talos_organizations::can_access_resource(
        db_pool,
        *user_id,
        resource_user_id,
        resource_org_id,
        min_role,
    )
    .await
    {
        return Err(async_graphql::Error::new("Resource not found or access denied").extend_safe());
    }
    Ok(())
}

/// Re-export validation functions from the validation module.
///
/// MCP-1037 (2026-05-15): `validate_payload_size` + `MAX_PAYLOAD_SIZE`
/// previously had a duplicate definition here. The active caller
/// (`workflows/mutations.rs`) imported the schema/mod.rs copy via the
/// same path; the canonical `validation::validate_payload_size` had
/// zero callers despite being the one cited by `validate_json_field`
/// internally. Same drift hazard as MCP-1002 (BLOCKED_TABLES) and
/// MCP-1019 (schema_query_patch fragment) — two copies of a
/// security-critical limit eventually diverge. The duplicate was
/// removed; `validate_payload_size` is now re-exported below so the
/// existing `use ::validate_payload_size` import in
/// `workflows/mutations.rs:12` keeps resolving against the canonical
/// `validation::validate_payload_size` (which uses `safe_err` for
/// scrubber compatibility per MCP-1023).
pub use crate::validation::{
    validate_api_key_expires_in_days, validate_description_content, validate_display_name,
    validate_max_concurrent_executions, validate_payload_size, validate_resource_name,
    validate_secret_value, validate_short_text_field, validate_text_field, validate_vault_key_path,
};

/// Maintain the `workflow_module_refs` junction table for a workflow save (create or update).
pub async fn sync_workflow_module_refs(
    db_pool: &sqlx::Pool<sqlx::Postgres>,
    workflow_id: uuid::Uuid,
    graph_json: &str,
) {
    let module_ids = ParallelWorkflowEngine::extract_module_ids(graph_json);

    // Best-effort: a failed sync warns, it doesn't fail the workflow save.
    // The repo method aborts before the INSERT if the DELETE fails, matching
    // the previous inline two-statement semantics.
    let repo = talos_workflow_repository::WorkflowRepository::new(db_pool.clone());
    if let Err(e) = repo.replace_module_refs(workflow_id, &module_ids).await {
        tracing::warn!(
            "sync_workflow_module_refs: sync failed for workflow {}: {}",
            workflow_id,
            e
        );
    }
}

/// Internal diff result between two graph JSON strings.
pub(crate) struct GraphDiff {
    pub nodes_added: i32,
    pub nodes_removed: i32,
    pub nodes_changed: i32,
    pub edges_added: i32,
    pub edges_removed: i32,
}

/// Compute diff between two graph JSON strings (published vs draft or version vs version).
pub(crate) fn compute_graph_diff(graph_a_str: &str, graph_b_str: &str) -> GraphDiff {
    let graph_a: serde_json::Value =
        serde_json::from_str(graph_a_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));
    let graph_b: serde_json::Value =
        serde_json::from_str(graph_b_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    let nodes_a = graph_a
        .get("nodes")
        .and_then(|n| n.as_array())
        .cloned()
        .unwrap_or_default();
    let nodes_b = graph_b
        .get("nodes")
        .and_then(|n| n.as_array())
        .cloned()
        .unwrap_or_default();
    let edges_a = graph_a
        .get("edges")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    let edges_b = graph_b
        .get("edges")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();

    let nodes_a_map: std::collections::HashMap<String, &serde_json::Value> = nodes_a
        .iter()
        .filter_map(|n| {
            n.get("id")
                .and_then(|v| v.as_str())
                .map(|id| (id.to_string(), n))
        })
        .collect();
    let nodes_b_map: std::collections::HashMap<String, &serde_json::Value> = nodes_b
        .iter()
        .filter_map(|n| {
            n.get("id")
                .and_then(|v| v.as_str())
                .map(|id| (id.to_string(), n))
        })
        .collect();

    let mut nodes_added = 0i32;
    let mut nodes_removed = 0i32;
    let mut nodes_changed = 0i32;

    for id in nodes_b_map.keys() {
        if !nodes_a_map.contains_key(id) {
            nodes_added += 1;
        }
    }
    for id in nodes_a_map.keys() {
        if !nodes_b_map.contains_key(id) {
            nodes_removed += 1;
        }
    }
    for (id, node_a) in &nodes_a_map {
        if let Some(node_b) = nodes_b_map.get(id) {
            let type_a = node_a.get("type");
            let type_b = node_b.get("type");
            let data_a = node_a.get("data");
            let data_b = node_b.get("data");
            if type_a != type_b || data_a != data_b {
                nodes_changed += 1;
            }
        }
    }

    // Edge diff: compare by (source, target) pairs
    let edge_key = |e: &serde_json::Value| -> String {
        let src = e.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let tgt = e.get("target").and_then(|v| v.as_str()).unwrap_or("");
        format!("{}->{}", src, tgt)
    };
    let edges_a_set: std::collections::HashSet<String> = edges_a.iter().map(edge_key).collect();
    let edges_b_set: std::collections::HashSet<String> = edges_b.iter().map(edge_key).collect();

    let edges_added = edges_b_set.difference(&edges_a_set).count() as i32;
    let edges_removed = edges_a_set.difference(&edges_b_set).count() as i32;

    GraphDiff {
        nodes_added,
        nodes_removed,
        nodes_changed,
        edges_added,
        edges_removed,
    }
}

/// Request metadata for audit logging
#[derive(Clone)]
pub struct RequestMetadata {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Distributed trace ID propagated from the frontend via the X-Trace-ID header.
#[derive(Clone, Debug)]
pub struct TraceId(pub String);

#[cfg(test)]
mod pre_2fa_gate_tests {
    use super::pre_2fa_operation_allowed;

    #[test]
    fn allows_me_query() {
        assert!(pre_2fa_operation_allowed(
            "query Me { me { id email twoFactorEnabled isTwoFactorVerified } }",
            None
        ));
    }

    #[test]
    fn allows_auth_bootstrap_mutations() {
        assert!(pre_2fa_operation_allowed(
            "mutation V($i: VerifyTwoFactorInput!) { verifyTwoFactor(input: $i) { user { id } } }",
            None
        ));
        assert!(pre_2fa_operation_allowed("mutation { logout }", None));
        assert!(pre_2fa_operation_allowed(
            "mutation R { refreshToken { user { id } } }",
            None
        ));
    }

    #[test]
    fn blocks_sensitive_reads() {
        // The exact P3 exploit surface: decrypted agent memory + secrets.
        assert!(!pre_2fa_operation_allowed(
            "query { actorMemories(actorId: \"x\") { id value } }",
            None
        ));
        assert!(!pre_2fa_operation_allowed(
            "query { secrets { keyPath } }",
            None
        ));
        assert!(!pre_2fa_operation_allowed(
            "query { workflows { id } }",
            None
        ));
    }

    #[test]
    fn blocks_mixed_operation_with_one_disallowed_field() {
        // `me` is allowed but `workflows` is not — the whole op is refused.
        assert!(!pre_2fa_operation_allowed(
            "query { me { id } workflows { id } }",
            None
        ));
    }

    #[test]
    fn cannot_smuggle_disallowed_field_via_fragment() {
        let q = "query { ...F } fragment F on QueryRoot { secrets { keyPath } }";
        assert!(!pre_2fa_operation_allowed(q, None));
    }

    #[test]
    fn allows_me_via_fragment() {
        let q = "query { ...F } fragment F on QueryRoot { me { id } }";
        assert!(pre_2fa_operation_allowed(q, None));
    }

    #[test]
    fn unparseable_query_fails_closed() {
        assert!(!pre_2fa_operation_allowed("query { unterminated", None));
    }

    #[test]
    fn multi_operation_requires_matching_name() {
        let q = "query A { me { id } } query B { workflows { id } }";
        // Selecting the safe op by name is allowed…
        assert!(pre_2fa_operation_allowed(q, Some("A")));
        // …the unsafe one is blocked…
        assert!(!pre_2fa_operation_allowed(q, Some("B")));
        // …and an ambiguous (unnamed) selection over multiple ops fails closed.
        assert!(!pre_2fa_operation_allowed(q, None));
    }

    #[test]
    fn introspection_is_allowed() {
        assert!(pre_2fa_operation_allowed("query { __typename }", None));
        assert!(pre_2fa_operation_allowed(
            "query { __schema { queryType { name } } }",
            None
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_graphql::{EmptyMutation, EmptySubscription, Object, Schema};
    use talos_api_keys::ApiKeyScope;

    struct TestQuery;

    #[Object]
    impl TestQuery {
        async fn protected_read(&self, ctx: &Context<'_>) -> Result<String> {
            require_scope(ctx, ApiKeyScope::WorkflowsRead)?;
            Ok("success".to_string())
        }

        async fn protected_admin(&self, ctx: &Context<'_>) -> Result<String> {
            require_scope(ctx, ApiKeyScope::Admin)?;
            Ok("admin_success".to_string())
        }

        async fn two_fa_gated(&self, ctx: &Context<'_>) -> Result<String> {
            require_2fa(ctx)?;
            Ok("2fa_success".to_string())
        }
    }

    /// Lock in the two distinct `require_2fa` failure messages (2026-07-06).
    /// The missing-data arm fires for UNAUTHENTICATED requests (expired
    /// session, no token) — pre-fix it reused the 2FA message, sending
    /// expired-session script users hunting for a nonexistent 2FA problem.
    /// It must name the real condition and signpost API keys; only the
    /// authenticated-but-unverified arm may mention Two-Factor.
    #[tokio::test]
    async fn test_require_2fa_error_messages() {
        let schema = Schema::build(TestQuery, EmptyMutation, EmptySubscription).finish();

        // Arm 1: no auth data at all (expired session / anonymous request).
        let res = schema
            .execute(async_graphql::Request::new("{ twoFaGated }"))
            .await;
        assert_eq!(res.errors.len(), 1);
        let msg = &res.errors[0].message;
        assert!(
            msg.contains("Authentication required") && msg.contains("API key"),
            "missing-data arm must name the real condition and signpost API keys, got: {msg}"
        );
        assert!(
            !msg.contains("Two-Factor"),
            "missing-data arm must NOT claim a 2FA problem, got: {msg}"
        );

        // Arm 2: authenticated but pre-2FA (TOTP user not yet verified).
        let res = schema
            .execute(
                async_graphql::Request::new("{ twoFaGated }")
                    .data(Uuid::new_v4())
                    .data(IsTwoFactorVerified(false)),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert!(
            res.errors[0]
                .message
                .contains("Two-Factor Authentication required"),
            "pre-2FA arm keeps the genuine 2FA message, got: {}",
            res.errors[0].message
        );

        // Happy path: verified session passes.
        let res = schema
            .execute(
                async_graphql::Request::new("{ twoFaGated }")
                    .data(Uuid::new_v4())
                    .data(IsTwoFactorVerified(true)),
            )
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
    }

    #[tokio::test]
    async fn test_require_scope() {
        let schema = Schema::build(TestQuery, EmptyMutation, EmptySubscription).finish();

        let req = async_graphql::Request::new("{ protectedRead }").data(Uuid::new_v4());
        let res = schema.execute(req).await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors, but got {:?}",
            res.errors
        );

        let req = async_graphql::Request::new("{ protectedRead }");
        let res = schema.execute(req).await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Authentication required"));

        let req = async_graphql::Request::new("{ protectedRead }")
            .data(ApiKeyScopes(vec![ApiKeyScope::WorkflowsRead]));
        let res = schema.execute(req).await;
        assert_eq!(res.errors.len(), 0);

        let req = async_graphql::Request::new("{ protectedRead }")
            .data(ApiKeyScopes(vec![ApiKeyScope::SecretsRead]));
        let res = schema.execute(req).await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Insufficient API key permissions");

        let req = async_graphql::Request::new("{ protectedRead }")
            .data(ApiKeyScopes(vec![ApiKeyScope::Admin]));
        let res = schema.execute(req).await;
        assert_eq!(res.errors.len(), 0);

        let req = async_graphql::Request::new("{ protectedAdmin }")
            .data(ApiKeyScopes(vec![ApiKeyScope::WorkflowsRead]));
        let res = schema.execute(req).await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Insufficient API key permissions");
    }

    /// N T6-N4: pin the documented session-bypass behavior of
    /// `require_scope`. A session-authenticated request (cookie-based,
    /// `Uuid` in ctx but no `ApiKeyScopes`) passes any scope check —
    /// even `Admin` — because sessions carry full per-user privilege
    /// and API-key scopes are deliberate downgrades. This is the
    /// documented intent (mod.rs:74-94) but it's exactly the kind of
    /// design the r277 mandate ("require_scope(Admin) session-bypasses;
    /// use require_platform_admin for system-wide ops") tightened the
    /// SCOPE of: per-user-admin operations are fine; cross-tenant
    /// admin ops MUST go through `require_platform_admin` (which gates
    /// on org_membership.role IN ('owner','admin')).
    ///
    /// If a future refactor tightens `require_scope` to fail on Admin
    /// for sessions, this test fails — and the contributor can either
    /// (a) update the test if the policy intentionally changed, or
    /// (b) revert. Either way the change is visible.
    #[tokio::test]
    async fn require_scope_admin_passes_for_session_authenticated_request() {
        let schema = Schema::build(TestQuery, EmptyMutation, EmptySubscription).finish();

        // Session-only context: Uuid present, no ApiKeyScopes. Should
        // pass `protectedAdmin` despite Admin being the required scope.
        let req = async_graphql::Request::new("{ protectedAdmin }").data(Uuid::new_v4());
        let res = schema.execute(req).await;
        assert!(
            res.errors.is_empty(),
            "Session auth should bypass require_scope(Admin) (per-user privilege model). \
             If this test fails, decide: did the policy intentionally tighten? Update the \
             test. Otherwise the change is a regression — sessions must keep full \
             per-user privilege. Errors: {:?}",
            res.errors
        );
    }

    /// Companion: an unauthenticated request (no Uuid, no ApiKeyScopes)
    /// must FAIL the protectedAdmin gate. Pins the failure side of the
    /// session-bypass — the bypass is per-session, not blanket.
    #[tokio::test]
    async fn require_scope_admin_fails_for_unauthenticated_request() {
        let schema = Schema::build(TestQuery, EmptyMutation, EmptySubscription).finish();
        let req = async_graphql::Request::new("{ protectedAdmin }");
        let res = schema.execute(req).await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Authentication required"));
    }

    /// S4/S6 (Low): the `sqlx::Error::extend_safe()` impl is the canonical
    /// safe shape — log the real error server-side, return a STATIC generic
    /// message. The client-facing message must NOT carry the raw sqlx text
    /// (table names, column names, role/pool internals). This is the shape
    /// the tenant-scope / commit / resolve-personal-org map_err closures
    /// were converted to in the S6 sweep.
    #[test]
    fn sqlx_error_extend_safe_returns_static_message_not_raw() {
        // A sqlx error whose Display carries internal detail we must not leak.
        let raw = sqlx::Error::Protocol(
            "tenant scope: column workflows.org_id role app_tenant denied".to_string(),
        );
        let leaked = raw.to_string();
        let gql = raw.extend_safe();
        assert_eq!(
            gql.message, "Database operation failed",
            "client message must be the static generic, not the raw sqlx text"
        );
        assert!(
            !gql.message.contains("org_id") && !gql.message.contains("app_tenant"),
            "internal schema/role detail must never reach the client; leaked={leaked}"
        );
    }

    /// S6 (Low): the post-sweep tenant-scope / commit failure messages are
    /// fixed, non-interpolated constants — they carry no `{e}` payload. Pin
    /// the exact client strings so a future refactor can't silently
    /// reintroduce error interpolation behind `.extend_safe()`.
    #[test]
    fn s6_static_scope_messages_carry_no_error_payload() {
        for msg in ["Request scope error", "Request could not be completed"] {
            let gql = async_graphql::Error::new(msg).extend_safe();
            assert_eq!(gql.message, msg);
            // None of the internal markers we strip should ever appear.
            assert!(!gql.message.contains("sqlx"));
            assert!(!gql.message.contains("org_id"));
            assert!(!gql.message.contains(": ")); // no "context: <raw>" shape
        }
    }

    /// S6 (Low): the static client messages are NOT on the legacy
    /// substring whitelist — they ride the explicit `extensions.safe=true`
    /// marker set by `.extend_safe()`, not the prose-substring fallback.
    /// This documents that we did not widen the whitelist to pass them.
    #[test]
    fn s6_scope_messages_are_not_whitelist_substrings() {
        assert!(!is_safe_error_substring("Request scope error"));
        assert!(!is_safe_error_substring("Request could not be completed"));
        // Legitimate whitelisted prose still passes (regression guard).
        assert!(is_safe_error_substring("Not found"));
        assert!(is_safe_error_substring("Access denied"));
    }
}
