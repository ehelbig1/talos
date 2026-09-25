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
pub mod ops_alerts;
pub mod organizations;
pub mod platform;
pub mod secrets;
pub mod security;
pub mod webhooks;
pub mod workflows;

mod mutations;
mod queries;
// `pub` so `refresh_dlq_permissions` — the DLQ subscription's periodic
// permission refresh, which NARROWS on an unreadable read — can be driven
// against a real database from `controller/tests/fail_open_gate_tests`.
// The rest of the module is the `#[Subscription]` impl, which is reachable
// only through the schema.
pub mod subscriptions;
pub mod throttle;
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
/// The session's JWT records a VERIFIED second factor
/// (`Claims::second_factor_verified`). Injected for session requests only; an
/// API-key request carries none, and absence reads as `false`.
pub struct SecondFactorVerified(pub bool);

/// When present in the GraphQL context, indicates the API key is scoped
/// to a specific organization. Resolvers should restrict resource access
/// to only resources within this org (or owned by the user directly).
pub struct ApiKeyOrgScope(pub Uuid);

/// Cross-crate MCP bearer-token cache invalidation hook (2026-07-24).
///
/// The bcrypt verification cache lives in `talos-mcp-handlers::auth`
/// (keyed by the token's SHA-256 lookup hash), and the workspace dep
/// direction forbids talos-api from depending on that crate. The
/// controller — which depends on BOTH — injects this wrapper into the
/// GraphQL schema data at wiring time (`bootstrap/services.rs`) with a
/// closure over `talos_mcp_handlers::auth::invalidate_agent_token_cache`.
/// `revoke_mcp_agent` calls it after a successful DELETE so a revoked
/// bearer token misses the cache immediately instead of surviving up to
/// the ~10 s TTL (+ 3 s sweep).
///
/// The closure takes the revoked agent's UUID (the mutation never holds
/// the token, so it can't compute the lookup hash itself) and returns the
/// number of cache entries removed. Fail-safe by construction: when this
/// isn't present in the schema data (`ctx.data_opt` → `None`), resolvers
/// skip the call and the TTL + background sweep remain the backstop.
pub struct McpTokenCacheInvalidator(pub std::sync::Arc<dyn Fn(Uuid) -> usize + Send + Sync>);

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

/// Scrub a GraphQL response's errors for a NON-development deployment, in
/// place. ONE home for the policy `graphql_handler` applies (2026-09-10 — the
/// WebSocket lane streamed responses to the client UNSCRUBBED, so a resolver
/// error carrying a schema name or query text reached a browser over `/ws`
/// while the same error over `/graphql` was collapsed).
///
/// Two-layer policy, unchanged from the HTTP handler:
///   1. EXPLICIT MARKER (preferred): an error carrying `extensions.safe = true`
///      (set by `.extend_safe()`) passes through verbatim — [`is_safe_error`].
///   2. SUBSTRING FALLBACK: [`is_safe_error_substring`] keeps legacy
///      user-facing messages that have not migrated to `.extend_safe()`.
/// Everything else becomes `"Internal server error"`; the original is logged
/// server-side. `is_development` is a parameter so the policy is testable;
/// callers use [`scrub_response_errors`], which reads `talos_config`.
pub fn scrub_response_errors_with(response: &mut async_graphql::Response, is_development: bool) {
    if is_development {
        return;
    }
    for error in &mut response.errors {
        tracing::error!("GraphQL Error: {:?}", error);
        if is_safe_error(error) {
            continue;
        }
        if !is_safe_error_substring(error.message.as_str()) {
            error.message = "Internal server error".to_string();
        }
    }
}

/// [`scrub_response_errors_with`] under the process's own environment.
pub fn scrub_response_errors(response: &mut async_graphql::Response) {
    scrub_response_errors_with(response, talos_config::is_development());
}

/// Is the operation this request selects a `subscription`? (2026-09-10.)
///
/// The graphql-ws `subscribe` / `start` frames were handed to
/// `Schema::execute_stream` unexamined, and `execute_stream` runs QUERIES and
/// MUTATIONS too — one-item streams — so the WebSocket lane was a second
/// mutation transport with none of the HTTP lane's CSRF discipline. Returns
/// `Ok(false)` for a query or mutation and `Err` when the document does not
/// parse or names no single operation (an operation that cannot be classified
/// must be refused, not executed); the caller rejects both.
pub fn operation_is_subscription(
    query: &str,
    operation_name: Option<&str>,
) -> Result<bool, String> {
    use async_graphql::parser::types::{DocumentOperations, OperationType};

    let doc = async_graphql::parser::parse_query(query).map_err(|e| e.to_string())?;
    let op = match &doc.operations {
        DocumentOperations::Single(op) => &op.node,
        DocumentOperations::Multiple(ops) => match operation_name {
            Some(name) => ops
                .get(name)
                .map(|op| &op.node)
                .ok_or_else(|| format!("operation '{name}' not found in document"))?,
            None if ops.len() == 1 => &ops.values().next().expect("len==1").node,
            None => {
                return Err(
                    "operationName is required when a document has several operations".into(),
                )
            }
        },
    };
    Ok(op.ty == OperationType::Subscription)
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

/// Why a privileged operation was refused. The caller-facing text says what
/// to do; none of it reveals anything about another account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondFactorRefusal {
    /// An API key: keys skip 2FA by design, so they cannot stand in for it.
    ApiKey,
    /// The session is still waiting for its 2FA code.
    Pending,
    /// No second factor was verified for this session (a password-only or
    /// OAuth login, or a session from before enrolment).
    NotVerified,
    /// The account has no second factor enrolled (or it was removed).
    NotEnrolled,
}

impl SecondFactorRefusal {
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::ApiKey => {
                "This operation requires an interactive session with two-factor \
                 authentication; API keys cannot perform it."
            }
            Self::Pending => "Two-Factor Authentication required. Please verify your identity.",
            Self::NotVerified => {
                "This operation requires a session verified with two-factor \
                 authentication. Sign in again and enter your authentication code."
            }
            Self::NotEnrolled => {
                "This operation requires two-factor authentication. Enable it under \
                 Settings → Security, then sign in again."
            }
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::Pending => "pending",
            Self::NotVerified => "not_verified",
            Self::NotEnrolled => "not_enrolled",
        }
    }
}

/// `verifyTwoFactor` refuses a session that is not waiting for a 2FA code
/// (password-only, or already verified): it completes a login, and there is
/// none to complete.
pub const NO_PENDING_SECOND_FACTOR: &str =
    "This session is not waiting for a two-factor code. Sign in to verify one.";

/// The privileged-operation decision, from facts the caller has gathered.
/// `enrolled` is `None` until it is read, and it is read only when every
/// cheaper condition has already passed.
pub fn second_factor_decision(
    api_key: bool,
    pending: bool,
    verified: bool,
    enrolled: Option<bool>,
) -> std::result::Result<(), SecondFactorRefusal> {
    if api_key {
        return Err(SecondFactorRefusal::ApiKey);
    }
    if pending {
        return Err(SecondFactorRefusal::Pending);
    }
    if !verified {
        return Err(SecondFactorRefusal::NotVerified);
    }
    match enrolled {
        Some(true) => Ok(()),
        _ => Err(SecondFactorRefusal::NotEnrolled),
    }
}

/// The session a password change needs, from facts the caller has gathered.
///
/// Not the privileged tier: an account with no second factor enrolled must
/// still be able to change a leaked password (the current password is the
/// proof), so a password-only session passes. What it refuses: an API key (a
/// long-lived bearer token must not be able to take over the account's
/// sign-in credential), a session still waiting for its 2FA code, and — on an
/// account WITH 2FA enrolled — a session that did not verify it, so a stolen
/// password-only token cannot rotate the password out from under the owner.
pub fn password_change_decision(
    api_key: bool,
    pending: bool,
    verified: bool,
    enrolled: bool,
) -> std::result::Result<(), SecondFactorRefusal> {
    if api_key {
        return Err(SecondFactorRefusal::ApiKey);
    }
    if pending {
        return Err(SecondFactorRefusal::Pending);
    }
    if enrolled && !verified {
        return Err(SecondFactorRefusal::NotVerified);
    }
    Ok(())
}

/// Gate for the PRIVILEGED operations — key material and security controls
/// (master-key and DEK rotation, the re-encryption sweeps, API-key lifecycle,
/// capability grants, audit settings, ownership transfer).
///
/// `require_2fa` only refuses a session that is half-way through a 2FA login:
/// an account with no second factor enrolled passes it on a password alone,
/// and every API-key request passes it. This gate requires, in order: not an
/// API key; not pending; a second factor VERIFIED for this session
/// (`SecondFactorVerified`, minted only by a 2FA login or by the enrolling
/// session); and 2FA still enrolled on the account now — one primary-key read,
/// so disabling 2FA withdraws the privilege at once rather than when the
/// session expires. A read failure refuses.
pub async fn require_second_factor(ctx: &Context<'_>) -> Result<()> {
    let (outcome, result) = evaluate_second_factor(ctx).await;
    // ONE recording site, for PERMITTED as well as every refusal. Counting
    // only refusals would leave the series unable to tell a deployment nobody
    // has been refused on from one whose gate is not wired — which is the
    // reading this package exists to remove, so it must not be reintroduced by
    // counting half the outcomes.
    talos_metrics::record_privileged_op(outcome);
    if !outcome.permitted() {
        // Kept at INFO and under `talos_audit` with the same `event_kind` and
        // `reason` vocabulary the four policy refusals have carried since
        // package CO, now covering the unauthenticated and unreadable arms too
        // — those used to reach this line not at all.
        tracing::info!(
            target: "talos_audit",
            event_kind = "privileged_op_refused",
            reason = outcome.as_str(),
            user_id = ?ctx.data_opt::<Uuid>(),
            "privileged operation refused: second factor not satisfied"
        );
    }
    result
}

/// The verdict and the caller-facing result, together.
///
/// Split out so `require_second_factor` has exactly one place that records and
/// one place that logs, while every error MESSAGE stays byte-identical to what
/// package CO shipped — those sentences are what a caller sees, and three of
/// them (the expired-session guidance, "Authentication required", "Database
/// error") are deliberately different from each other.
async fn evaluate_second_factor(
    ctx: &Context<'_>,
) -> (talos_metrics::PrivilegedOpOutcome, Result<()>) {
    use talos_metrics::PrivilegedOpOutcome as Outcome;
    let api_key = ctx.data_opt::<ApiKeyScopes>().is_some();
    // A request with neither marker is unauthenticated: `require_2fa`'s own
    // missing-data arm names that condition, so defer to it.
    if !api_key && ctx.data_opt::<IsTwoFactorVerified>().is_none() {
        return (Outcome::Unauthenticated, require_2fa(ctx));
    }
    let pending = !ctx.data_opt::<IsTwoFactorVerified>().is_some_and(|v| v.0);
    let verified = ctx.data_opt::<SecondFactorVerified>().is_some_and(|v| v.0);
    let early = second_factor_decision(api_key, pending, verified, Some(true));
    let decision = if early.is_err() {
        early
    } else {
        let Some(user_id) = ctx.data_opt::<Uuid>().copied() else {
            return (
                Outcome::Unauthenticated,
                Err(async_graphql::Error::new("Authentication required").extend_safe()),
            );
        };
        let auth_service = match ctx.data::<std::sync::Arc<talos_auth::AuthService>>() {
            Ok(svc) => svc,
            // The gate cannot be evaluated without the service. Refused, and
            // counted as unreadable rather than as a policy decision.
            Err(e) => return (Outcome::Unreadable, Err(e)),
        };
        let enrolled = match auth_service.get_user(user_id).await {
            Ok(user) => user.totp_enabled.unwrap_or(false),
            Err(e) => {
                tracing::error!(
                    %user_id,
                    "require_second_factor: enrolment read failed; refusing: {e}"
                );
                return (
                    Outcome::Unreadable,
                    Err(async_graphql::Error::new("Database error").extend_safe()),
                );
            }
        };
        second_factor_decision(api_key, pending, verified, Some(enrolled))
    };
    match decision {
        Ok(()) => (Outcome::Permitted, Ok(())),
        Err(refusal) => (
            privileged_outcome_for(refusal),
            Err(async_graphql::Error::new(refusal.message()).extend_safe()),
        ),
    }
}

/// The ONE mapping from a policy refusal to its metric label.
///
/// A `match` rather than a string, so a new `SecondFactorRefusal` variant fails
/// to compile until it is given a label — the same reason
/// `talos_workflow_job_protocol::verify_failure_class` dropped its catch-all.
/// The tokens are pinned equal to `SecondFactorRefusal::as_str` by
/// `refusal_labels_match_the_caller_facing_reason`, because the log line and
/// the series must not drift apart.
const fn privileged_outcome_for(
    refusal: SecondFactorRefusal,
) -> talos_metrics::PrivilegedOpOutcome {
    use talos_metrics::PrivilegedOpOutcome as Outcome;
    match refusal {
        SecondFactorRefusal::ApiKey => Outcome::ApiKey,
        SecondFactorRefusal::Pending => Outcome::Pending,
        SecondFactorRefusal::NotVerified => Outcome::NotVerified,
        SecondFactorRefusal::NotEnrolled => Outcome::NotEnrolled,
    }
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
    let (outcome, result) = evaluate_platform_admin(ctx).await;
    // ONE recording site, permitted included — see `require_second_factor` for
    // why the denominator is part of the signal.
    talos_metrics::record_platform_admin_check(outcome);
    result
}

/// The verdict and the caller-facing result, together. Every message is
/// byte-identical to the pre-instrumentation gate.
async fn evaluate_platform_admin(
    ctx: &Context<'_>,
) -> (talos_metrics::PlatformAdminOutcome, Result<()>) {
    use talos_metrics::PlatformAdminOutcome as Outcome;
    let Some(user_id) = ctx.data_opt::<Uuid>().copied() else {
        return (
            Outcome::Unauthenticated,
            Err(async_graphql::Error::new("Authentication required").extend_safe()),
        );
    };

    let db_pool = match ctx.data::<sqlx::Pool<sqlx::Postgres>>() {
        Ok(p) => p,
        // No pool, so the rule cannot be read. Refused, and counted as
        // unreadable rather than as "not an admin" — a caller told they lack a
        // privilege they may well hold sends an operator to the wrong place.
        Err(e) => return (Outcome::Unreadable, Err(e)),
    };

    // M T6-1: delegate to the canonical helper so the column source
    // (post-migration `users.is_platform_admin`) is in one place.
    // Pre-fix this inlined the same `EXISTS(SELECT 1 FROM
    // organization_members ...)` SQL the actor-repository helper
    // had — drift risk + the conflation bug fixed in the migration.
    let actor_repo = talos_actor_repository::ActorRepository::new(db_pool.clone());
    let is_admin = match actor_repo.is_platform_admin(user_id).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("require_platform_admin db check failed: {}", e);
            return (
                Outcome::Unreadable,
                Err(async_graphql::Error::new("Database error").extend_safe()),
            );
        }
    };

    if !is_admin {
        return (
            Outcome::NotAdmin,
            Err(
                async_graphql::Error::new("Only platform admins can perform this operation")
                    .extend_safe(),
            ),
        );
    }

    (Outcome::Permitted, Ok(()))
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

#[cfg(test)]
mod ws_lane_guard_tests {
    use super::{operation_is_subscription, scrub_response_errors_with, SafeErrorExtensions};

    #[test]
    fn a_subscription_is_classified_as_one() {
        assert_eq!(
            operation_is_subscription("subscription { executionUpdates { id } }", None),
            Ok(true)
        );
    }

    #[test]
    fn a_query_and_a_mutation_are_not() {
        assert_eq!(operation_is_subscription("{ me { id } }", None), Ok(false));
        assert_eq!(
            operation_is_subscription("mutation { deleteWorkflow(id: \"x\") }", None),
            Ok(false)
        );
    }

    #[test]
    fn the_named_operation_decides_in_a_multi_operation_document() {
        let doc =
            "subscription S { executionUpdates { id } } mutation M { deleteWorkflow(id: \"x\") }";
        assert_eq!(operation_is_subscription(doc, Some("S")), Ok(true));
        assert_eq!(operation_is_subscription(doc, Some("M")), Ok(false));
        // No name over several operations: cannot classify ⇒ Err (refused).
        assert!(operation_is_subscription(doc, None).is_err());
        assert!(operation_is_subscription(doc, Some("Nope")).is_err());
    }

    #[test]
    fn an_unparseable_document_is_an_error_not_a_pass() {
        assert!(operation_is_subscription("subscription {", None).is_err());
    }

    fn response_with(errors: Vec<async_graphql::ServerError>) -> async_graphql::Response {
        let mut r = async_graphql::Response::new(async_graphql::Value::Null);
        r.errors = errors;
        r
    }

    #[test]
    fn production_scrub_collapses_unmarked_errors_and_keeps_safe_ones() {
        let leaky = async_graphql::ServerError::new(
            "relation \"secrets\" does not exist at query SELECT value_enc FROM secrets",
            None,
        );
        let marked: async_graphql::ServerError = async_graphql::Error::new("anything at all")
            .extend_safe()
            .into_server_error(async_graphql::Pos::default());
        let legacy = async_graphql::ServerError::new("Not found", None);
        let mut resp = response_with(vec![leaky, marked, legacy]);
        scrub_response_errors_with(&mut resp, false);
        assert_eq!(resp.errors[0].message, "Internal server error");
        assert_eq!(resp.errors[1].message, "anything at all");
        assert_eq!(resp.errors[2].message, "Not found");
    }

    #[test]
    fn development_is_left_verbatim() {
        let leaky = async_graphql::ServerError::new("relation does not exist", None);
        let mut resp = response_with(vec![leaky]);
        scrub_response_errors_with(&mut resp, true);
        assert_eq!(resp.errors[0].message, "relation does not exist");
    }
}

#[cfg(test)]
mod second_factor_tests {
    use super::{
        password_change_decision, privileged_outcome_for, second_factor_decision,
        SecondFactorRefusal,
    };

    /// The metric label and the caller-facing `reason` must be the SAME token
    /// for every refusal.
    ///
    /// They are produced by two different functions in two different crates —
    /// `SecondFactorRefusal::as_str` writes the `talos_audit` log field, and
    /// `PrivilegedOpOutcome::as_str` writes the series label — so nothing but
    /// this test stops them drifting. If they drift, an operator who greps the
    /// log for a reason and then queries the counter for the same token gets an
    /// empty series and concludes the gate never refused, which is the exact
    /// misreading package DY exists to remove.
    #[test]
    fn refusal_labels_match_the_caller_facing_reason() {
        for refusal in [
            SecondFactorRefusal::ApiKey,
            SecondFactorRefusal::Pending,
            SecondFactorRefusal::NotVerified,
            SecondFactorRefusal::NotEnrolled,
        ] {
            assert_eq!(
                refusal.as_str(),
                privileged_outcome_for(refusal).as_str(),
                "{refusal:?}: log reason and metric label disagree"
            );
            // And a refusal never maps to the admitting value — a mapping that
            // returned `Permitted` would make every refusal invisible while
            // the per-value seed test above still passed.
            assert!(
                !privileged_outcome_for(refusal).permitted(),
                "{refusal:?} mapped to the admitting outcome"
            );
        }
    }

    /// The three NON-policy outcomes are values the refusal enum cannot
    /// produce, and that is the point: a caller who could not be identified, a
    /// rule that could not be READ, and a rule that said no are three
    /// different operator actions. Pinned so a future "simplification" that
    /// folds `unreadable` into a policy reason has to delete this.
    #[test]
    fn the_non_policy_outcomes_are_distinct_from_every_policy_refusal() {
        use talos_metrics::PrivilegedOpOutcome as O;
        let policy: Vec<&str> = [
            SecondFactorRefusal::ApiKey,
            SecondFactorRefusal::Pending,
            SecondFactorRefusal::NotVerified,
            SecondFactorRefusal::NotEnrolled,
        ]
        .iter()
        .map(|r| privileged_outcome_for(*r).as_str())
        .collect();
        for o in [O::Permitted, O::Unauthenticated, O::Unreadable] {
            assert!(
                !policy.contains(&o.as_str()),
                "{} collides with a policy refusal label",
                o.as_str()
            );
        }
        // Every value the enum declares is reachable from somewhere: four from
        // the policy mapping, three from the gate's own arms.
        assert_eq!(O::ALL.len(), policy.len() + 3);
    }

    /// A password change needs a session that is not an API key, not pending,
    /// and — only when 2FA is enrolled — verified. A password-only session on
    /// an account with nothing enrolled passes: the current password is its
    /// proof, and refusing it would leave that account no way to rotate a
    /// leaked password.
    #[test]
    fn a_password_change_needs_verification_only_when_enrolled() {
        for api_key in [false, true] {
            for pending in [false, true] {
                for verified in [false, true] {
                    for enrolled in [false, true] {
                        let got = password_change_decision(api_key, pending, verified, enrolled);
                        let want = if api_key {
                            Err(SecondFactorRefusal::ApiKey)
                        } else if pending {
                            Err(SecondFactorRefusal::Pending)
                        } else if enrolled && !verified {
                            Err(SecondFactorRefusal::NotVerified)
                        } else {
                            Ok(())
                        };
                        assert_eq!(got, want, "{api_key} {pending} {verified} {enrolled}");
                    }
                }
            }
        }
    }

    /// Every combination of the four facts: only "not an API key, not
    /// pending, verified, enrolled" passes, and each refusal names the FIRST
    /// failing condition in the documented order.
    #[test]
    fn only_a_verified_enrolled_session_passes() {
        for api_key in [false, true] {
            for pending in [false, true] {
                for verified in [false, true] {
                    for enrolled in [None, Some(false), Some(true)] {
                        let got = second_factor_decision(api_key, pending, verified, enrolled);
                        let want = if api_key {
                            Err(SecondFactorRefusal::ApiKey)
                        } else if pending {
                            Err(SecondFactorRefusal::Pending)
                        } else if !verified {
                            Err(SecondFactorRefusal::NotVerified)
                        } else if enrolled != Some(true) {
                            Err(SecondFactorRefusal::NotEnrolled)
                        } else {
                            Ok(())
                        };
                        assert_eq!(got, want, "{api_key} {pending} {verified} {enrolled:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn refusals_have_distinct_labels_and_messages() {
        let all = [
            SecondFactorRefusal::ApiKey,
            SecondFactorRefusal::Pending,
            SecondFactorRefusal::NotVerified,
            SecondFactorRefusal::NotEnrolled,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.as_str(), b.as_str());
                assert_ne!(a.message(), b.message());
            }
        }
    }

    /// SOURCE PIN, stated as textual: the privileged tier — operations that
    /// touch key material or create or expand privilege — calls
    /// `require_second_factor`, and the revocations (which REDUCE privilege and
    /// must stay quick in an incident) keep `require_2fa`. The DB test drives
    /// the gate through `rotateOrgDek` only; this pins every member.
    #[test]
    fn the_privileged_tier_calls_the_second_factor_gate() {
        let files = [
            (include_str!("security/mutations.rs"), "security"),
            (include_str!("platform/mutations.rs"), "platform"),
            (include_str!("organizations/mutations.rs"), "organizations"),
            (include_str!("actors/mutations.rs"), "actors"),
        ];
        let body = |name: &str| -> &'static str {
            let needle = format!("\n    async fn {name}(");
            let hits: Vec<(&'static str, usize)> = files
                .iter()
                .filter_map(|(src, _)| src.find(&needle).map(|i| (*src, i)))
                .collect();
            assert_eq!(hits.len(), 1, "{name}: exactly one resolver");
            let (src, i) = hits[0];
            // A resolver ends at the next resolver or at the impl's closing
            // brace — never at end of file, where a test module quoting the
            // gate would vouch for it.
            let rest = &src[i + 1..];
            let end = [rest.find("\n    async fn "), rest.find("\n}\n")]
                .into_iter()
                .flatten()
                .min()
                .map_or(src.len(), |e| i + 1 + e);
            &src[i..end]
        };
        const PRIVILEGED: [&str; 15] = [
            "create_api_key",
            "rotate_api_key",
            "register_mcp_agent",
            "rotate_dek",
            "rotate_org_dek",
            "rotate_master_key",
            "rotate_encryption_key",
            "re_encrypt_secrets",
            "re_encrypt_secrets_to_org",
            "re_encrypt_memories_to_org",
            "re_encrypt_outputs_to_org",
            "re_encrypt_module_payloads_to_org",
            "update_audit_settings",
            "grant_capability_ceiling",
            "transfer_ownership",
        ];
        for name in PRIVILEGED {
            let b = body(name);
            assert!(
                b.contains("require_second_factor(ctx).await?"),
                "{name}: privileged, must call require_second_factor"
            );
            assert!(
                !b.contains("require_2fa(ctx)?"),
                "{name}: must not keep the weaker gate"
            );
        }
        const REDUCING: [&str; 4] = [
            "revoke_api_key",
            "delete_api_key",
            "revoke_mcp_agent",
            "revoke_capability_ceiling",
        ];
        for name in REDUCING {
            let b = body(name);
            assert!(
                b.contains("require_2fa(ctx)?") && !b.contains("require_second_factor"),
                "{name}: reduces privilege, keeps require_2fa"
            );
        }
    }
}

/// The ONE lock every test that reads the process-global metrics registry
/// takes.
///
/// One home rather than one per module, and the reason is a failure this
/// package had: the throttle recorder test passed alone and failed beside its
/// siblings, because another test in the same binary refuses calls through the
/// same limiter and moves the same series. A per-module lock serialises a
/// module against itself and not against the binary, which is the shape that
/// looks correct and is not.
#[cfg(test)]
pub(crate) static METRICS_SERIES_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Production-path guards for the privileged-operation gate (package DY).
///
/// These drive the REAL `require_second_factor` through a real `async_graphql`
/// schema and read the counter out of a real registry — not the pure decision
/// function, and not the recorder in isolation. That matters because the two
/// things most likely to go wrong are invisible to either of those alone: a
/// gate that classifies correctly and never records, and a gate that records
/// only refusals (which leaves a refusal rate with no denominator, and makes a
/// deployment nobody has been refused on look exactly like one whose gate is
/// not wired — the reading this package exists to remove).
///
/// **Five of the seven outcomes are reachable with no database**, because each
/// short-circuits before the enrolment read: no markers at all is
/// `Unauthenticated`; an API key, a pending session and an unverified session
/// are all settled by `second_factor_decision`'s early pass; and a session that
/// passes every cheap check with no `AuthService` in the context is
/// `Unreadable` — the fail-closed arm, exercised here rather than asserted.
/// `Permitted` and `NotEnrolled` need a real `AuthService` and a user row, so
/// they are covered by `second_factor_tests` at the decision level and stated
/// as not driven end to end here.
#[cfg(test)]
mod privileged_gate_production_path_tests {
    use super::*;
    use async_graphql::{EmptyMutation, EmptySubscription, Object, Schema};
    use std::sync::Arc;
    use talos_metrics::PrivilegedOpOutcome as O;

    struct PrivilegedQuery;

    #[Object]
    impl PrivilegedQuery {
        /// Stands in for any of the fifteen privileged mutations — it calls
        /// the same gate they do, by the same name.
        async fn rotate_something(&self, ctx: &Context<'_>) -> Result<bool> {
            require_second_factor(ctx).await?;
            Ok(true)
        }
    }

    fn schema() -> Schema<PrivilegedQuery, EmptyMutation, EmptySubscription> {
        Schema::build(PrivilegedQuery, EmptyMutation, EmptySubscription).finish()
    }

    /// Install (idempotently) and return the process-global registry.
    fn registry() -> &'static Arc<talos_metrics::TalosMetrics> {
        talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("registry"));
        talos_metrics::global().expect("installed")
    }

    fn counts(m: &talos_metrics::TalosMetrics) -> Vec<(&'static str, u64)> {
        O::ALL
            .iter()
            .map(|o| {
                (
                    o.as_str(),
                    m.privileged_op_total
                        .with_label_values(&[o.as_str()])
                        .get()
                        .round() as u64,
                )
            })
            .collect()
    }

    /// Execute one request and assert EXACTLY the expected outcome moved, by
    /// exactly one. The "every other value moved by zero" half is what catches
    /// a recorder that ignores its argument, and the "by one" half catches a
    /// gate that records twice.
    async fn assert_records(req: async_graphql::Request, expected: O, expect_error: bool) {
        let _guard = super::METRICS_SERIES_LOCK.lock().await;
        let m = registry();
        let before = counts(m);
        let res = schema().execute(req).await;
        assert_eq!(
            res.errors.is_empty(),
            !expect_error,
            "caller-facing outcome changed: {:?}",
            res.errors
        );
        let after = counts(m);
        for ((name, b), (_, a)) in before.iter().zip(after.iter()) {
            let want = u64::from(*name == expected.as_str());
            assert_eq!(
                a - b,
                want,
                "outcome {name}: delta {} , expected {want} (gate under test: {})",
                a - b,
                expected.as_str()
            );
        }
    }

    /// No session marker and no API key: the request is unauthenticated, and
    /// that is its OWN outcome rather than a policy refusal — an operator
    /// reading `not_verified` would go looking for a 2FA problem on an account
    /// that never presented a session.
    #[tokio::test]
    async fn an_unauthenticated_request_is_counted_as_unauthenticated() {
        assert_records(
            async_graphql::Request::new("{ rotateSomething }"),
            O::Unauthenticated,
            true,
        )
        .await;
    }

    /// An API key is refused BY DESIGN — keys carry no second factor, so they
    /// cannot stand in for one — and the counter says so in its own value
    /// rather than folding into the generic refusal.
    #[tokio::test]
    async fn an_api_key_is_counted_as_api_key() {
        assert_records(
            async_graphql::Request::new("{ rotateSomething }")
                .data(ApiKeyScopes(vec![]))
                .data(Uuid::new_v4()),
            O::ApiKey,
            true,
        )
        .await;
    }

    /// A session half-way through its 2FA login.
    #[tokio::test]
    async fn a_pending_session_is_counted_as_pending() {
        assert_records(
            async_graphql::Request::new("{ rotateSomething }")
                .data(IsTwoFactorVerified(false))
                .data(Uuid::new_v4()),
            O::Pending,
            true,
        )
        .await;
    }

    /// A password-only or OAuth session: it authenticated, and it did not
    /// prove a second factor.
    #[tokio::test]
    async fn a_session_that_proved_no_second_factor_is_counted_as_not_verified() {
        assert_records(
            async_graphql::Request::new("{ rotateSomething }")
                .data(IsTwoFactorVerified(true))
                .data(Uuid::new_v4()),
            O::NotVerified,
            true,
        )
        .await;
    }

    /// The platform-admin gate is the SECOND surface this package
    /// instruments, and it needs its own production-path cases: a guard on one
    /// gate cannot see the other, and these two are separate functions with
    /// separate counters. Two of its four outcomes are drivable with no
    /// database (no caller id; no pool to read the rule from); `permitted` and
    /// `not_admin` need a real `users` row and are stated as not driven here.
    #[tokio::test]
    async fn the_platform_admin_gate_counts_its_own_outcomes() {
        use talos_metrics::PlatformAdminOutcome as A;

        struct AdminQuery;
        #[Object]
        impl AdminQuery {
            async fn admin_only(&self, ctx: &Context<'_>) -> Result<bool> {
                require_platform_admin(ctx).await?;
                Ok(true)
            }
        }

        let _guard = super::METRICS_SERIES_LOCK.lock().await;
        let m = registry();
        let read = |o: A| {
            m.platform_admin_checks_total
                .with_label_values(&[o.as_str()])
                .get()
                .round() as u64
        };
        let schema = Schema::build(AdminQuery, EmptyMutation, EmptySubscription).finish();

        // No caller id at all.
        let before = read(A::Unauthenticated);
        let res = schema
            .execute(async_graphql::Request::new("{ adminOnly }"))
            .await;
        assert_eq!(
            res.errors.len(),
            1,
            "an unidentified caller must be refused"
        );
        assert_eq!(read(A::Unauthenticated), before + 1);

        // A caller id, but the rule cannot be read — REFUSED, and counted as
        // unreadable rather than as "not an admin": telling a caller they lack
        // a privilege they may well hold sends an operator to the wrong place.
        let before = read(A::Unreadable);
        let res = schema
            .execute(async_graphql::Request::new("{ adminOnly }").data(Uuid::new_v4()))
            .await;
        assert_eq!(res.errors.len(), 1, "an unreadable rule must be refused");
        assert_eq!(read(A::Unreadable), before + 1);
        assert_eq!(
            read(A::NotAdmin),
            0,
            "an unreadable rule must not be reported as a policy refusal"
        );
    }

    /// THE FAIL-CLOSED ARM, exercised rather than asserted. Every cheap check
    /// passes and the enrolment rule cannot be read — here because no
    /// `AuthService` is in the context, in production because the read failed.
    /// The call must be REFUSED and counted as `unreadable`: a fault to fix,
    /// never a policy decision to respect, and never a grant.
    #[tokio::test]
    async fn an_unreadable_rule_refuses_and_is_counted_as_unreadable() {
        assert_records(
            async_graphql::Request::new("{ rotateSomething }")
                .data(IsTwoFactorVerified(true))
                .data(SecondFactorVerified(true))
                .data(Uuid::new_v4()),
            O::Unreadable,
            true,
        )
        .await;
    }
}

/// Why `talos_platform_admin_checks_total{outcome="unauthenticated"}` reads 0
/// on every deployment, pinned so the counter's HELP text cannot go stale.
///
/// `require_scope(Admin)` refuses a caller carrying neither `ApiKeyScopes` nor
/// a session `Uuid`. Every `require_platform_admin` call site runs it FIRST,
/// so the platform-admin gate is never reached by an anonymous caller and its
/// `unauthenticated` arm — which the function must still have to be total —
/// cannot be delivered by production. Measured live on 2026-09-23: an
/// unauthenticated `dekMigrationStatus` reached the resolver and moved the
/// counter by zero.
///
/// `require_second_factor` is the CONTRAST and the reason this is worth
/// pinning rather than assuming: none of its call sites has a scope gate in
/// front, so its own `unauthenticated` IS reachable and was observed moving
/// 0 -> 1 on the same fleet the same day.
///
/// TEXTUAL, and stated as such: it reads the resolver sources rather than the
/// call graph, so a gate reached through a helper is invisible to it.
#[cfg(test)]
mod platform_admin_reachability_pins {
    fn read(rel: &str) -> String {
        std::fs::read_to_string(rel).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
    }

    /// For each `require_platform_admin` call, look back a few lines for a
    /// `require_scope`. Every one must have it — that is the claim the HELP
    /// text makes.
    #[test]
    fn every_platform_admin_gate_sits_behind_the_scope_gate() {
        let mut checked = 0usize;
        for rel in [
            "src/schema/security/queries.rs",
            "src/schema/security/mutations.rs",
        ] {
            let body = read(rel);
            let lines: Vec<&str> = body.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let t = line.trim_start();
                if t.starts_with("//") || !line.contains("require_platform_admin(ctx)") {
                    continue;
                }
                checked += 1;
                let lo = i.saturating_sub(8);
                let has_scope = lines[lo..i].iter().any(|l| l.contains("require_scope("));
                assert!(
                    has_scope,
                    "{rel}:{}: require_platform_admin without require_scope above it. \
                     That makes talos_platform_admin_checks_total{{outcome=\"unauthenticated\"}} \
                     REACHABLE, so this pin and the counter's HELP text must be updated together.",
                    i + 1
                );
            }
        }
        assert!(
            checked >= 10,
            "expected the platform-admin gate at 10+ call sites, found {checked} — \
             the scan stopped matching and would vouch for nothing"
        );
    }

    /// The contrast, so the asymmetry is recorded rather than inferred: the
    /// privileged gate is NOT behind a scope gate, which is why its
    /// `unauthenticated` is reachable and the platform-admin one is not.
    #[test]
    fn the_privileged_gate_is_not_behind_the_scope_gate() {
        let body = read("src/schema/security/mutations.rs");
        let lines: Vec<&str> = body.lines().collect();
        let mut sites = 0usize;
        let mut behind_scope = 0usize;
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") || !line.contains("require_second_factor(ctx)") {
                continue;
            }
            sites += 1;
            let lo = i.saturating_sub(8);
            if lines[lo..i].iter().any(|l| l.contains("require_scope(")) {
                behind_scope += 1;
            }
        }
        assert!(
            sites >= 10,
            "expected 10+ privileged-gate sites, found {sites}"
        );
        assert_eq!(
            behind_scope, 0,
            "a privileged-gate call site gained a scope gate in front of it — its \
             `unauthenticated` outcome may no longer be reachable, which the \
             platform-admin counter's HELP text contrasts against"
        );
    }
}
