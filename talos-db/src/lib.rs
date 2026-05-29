// MCP-953 (2026-05-15): Dead `WorkflowRecord` struct + duplicate
// `get_workflow` helper removed — the canonical pair lives in
// `talos-workflow-repository::WorkflowRecord` / `WorkflowRepository::
// get_workflow` and is what every caller actually uses. The bare
// `talos-db` helpers had no callers (the deferred read-replica wire-in
// `init_read_replica_pool` is still kept below for the operator hook).
use anyhow::Context;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres, Transaction};
use talos_tenancy::{OrgScope, TenantReadScope};

/// RFC 0005 S3: the non-superuser / non-`BYPASSRLS` role that request-path
/// transactions run as (via `SET LOCAL ROLE`) so the RFC 0004 RLS
/// policies enforce even when the controller's underlying connection is a
/// superuser (the common in-cluster Postgres deploy). Provisioned by
/// migration `20260529220000_talos_app_role.sql`; reached only via
/// `SET ROLE` (the role is `NOLOGIN`), mirroring `talos_guest`.
pub const RLS_APP_ROLE: &str = "talos_app";

/// Whether the scoped-tx helpers wrap each transaction in
/// `SET LOCAL ROLE talos_app`. Gated by `TALOS_RLS_SET_ROLE` (default
/// OFF) so a deploy enables enforcement only after confirming the role +
/// grants are provisioned (migration applied) in that environment.
/// Read once — process env is immutable for the lifetime of the process.
fn rls_set_role_enabled() -> bool {
    static ENABLED: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
        matches!(
            std::env::var("TALOS_RLS_SET_ROLE").ok().as_deref(),
            Some("1") | Some("true") | Some("yes") | Some("on")
        )
    });
    *ENABLED
}

/// `"SET LOCAL ROLE talos_app; "` when enforcement is enabled, else `""`.
/// Pure (testable) mapping; the role name is a fixed constant — no caller
/// text, no injection surface.
fn rls_role_prefix_for(enabled: bool) -> &'static str {
    if enabled {
        "SET LOCAL ROLE talos_app; "
    } else {
        ""
    }
}

/// Prefix prepended to a scoped tx's GUC `SET LOCAL`s so the role + scope
/// are established in ONE round-trip. `SET LOCAL ROLE` is
/// transaction-scoped — it resets on commit/rollback, so there is no
/// pooled-connection leakage (same guarantee as the GUC `SET LOCAL`s).
fn rls_role_prefix() -> &'static str {
    rls_role_prefix_for(rls_set_role_enabled())
}

/// Begin a **tenant-scoped transaction** (RFC 0004): acquire a pooled
/// connection, open a transaction, and stamp `SET LOCAL
/// app.current_org_id` so every statement run on the returned
/// transaction is filtered by the org-isolation RLS policies. The caller
/// runs its queries on the returned `Transaction` and **must commit**
/// (drop = rollback).
///
/// This is the canonical primitive the repository layer (M3) routes
/// org-scoped data access through. `SET LOCAL` is transaction-scoped, so
/// the GUC is automatically cleared on commit/rollback — there is no
/// cross-request leakage through the connection pool (unlike a
/// session-level `SET`).
///
/// # Security prerequisite
///
/// RLS is enforced **only if the connecting role is neither a superuser
/// nor `BYPASSRLS`** — Postgres silently ignores policies for those
/// roles, which would make this primitive a no-op isolation-wise. The
/// controller MUST connect as a plain application role. (Tables may also
/// use `FORCE ROW LEVEL SECURITY` to apply policies even to the table
/// owner.) See RFC 0004 "Access & RLS".
pub async fn begin_org_scoped<'a>(
    pool: &'a Pool<Postgres>,
    scope: &OrgScope,
) -> anyhow::Result<Transaction<'a, Postgres>> {
    let mut tx = pool
        .begin()
        .await
        .context("begin tenant-scoped transaction")?;
    // SET LOCAL cannot bind parameters; `scope.set_local_org_sql()`
    // interpolates a `Uuid` (no caller text, no injection surface). The
    // optional `SET LOCAL ROLE talos_app` (RFC 0005 S3) rides in the same
    // simple-query round-trip so RLS enforces under a superuser
    // connection without an extra hop.
    use sqlx::Executor as _;
    let sql = format!("{}{}", rls_role_prefix(), scope.set_local_org_sql());
    (&mut *tx)
        .execute(sql.as_str())
        .await
        .context("set role + app.current_org_id for tenant scope")?;
    Ok(tx)
}

/// Begin a transaction carrying the **membership-union read backstop**
/// (RFC 0004): stamps `app.current_user_id` + `app.current_org_ids` so
/// the RLS policy can act as defense in depth behind the app-layer
/// `user_accessible_org_ids` checks — a row is visible if owned by the
/// user OR in any org the user belongs to. The caller runs its queries
/// on the returned tx and **must commit** (drop = rollback).
///
/// Use this for general read paths. For a single-org context (org-scoped
/// API key, creation context) use [`begin_org_scoped`]. Same
/// non-superuser-role prerequisite applies (see [`check_rls_role`]).
pub async fn begin_tenant_read_scoped<'a>(
    pool: &'a Pool<Postgres>,
    scope: &TenantReadScope,
) -> anyhow::Result<Transaction<'a, Postgres>> {
    let mut tx = pool
        .begin()
        .await
        .context("begin tenant-read-scoped transaction")?;
    // Both SET LOCALs in ONE round-trip via the simple-query protocol
    // (`Executor::execute(&str)`), instead of two extended-protocol
    // queries — keeps the per-scoped-read latency to begin + this + the
    // caller's query + commit.
    use sqlx::Executor as _;
    let sql = format!("{}{}", rls_role_prefix(), scope.set_local_sql());
    (&mut *tx)
        .execute(sql.as_str())
        .await
        .context("set role + app.current_user_id + app.current_org_ids")?;
    Ok(tx)
}

/// Convenience over [`begin_tenant_read_scoped`] for a **personal**
/// (per-user) table: opens a scoped tx that sets `app.current_user_id`
/// with an empty org list, so the RLS policy's `user_id = current_user_id`
/// clause matches. Use [`begin_tenant_read_scoped`] directly for tables
/// shared across orgs (pass the user's accessible org ids).
pub async fn begin_user_scoped(
    pool: &Pool<Postgres>,
    user_id: uuid::Uuid,
) -> anyhow::Result<Transaction<'_, Postgres>> {
    begin_tenant_read_scoped(pool, &TenantReadScope::new(user_id, Vec::new())).await
}

/// Whether the connecting DB role can enforce row-level security.
///
/// Postgres **silently ignores** RLS policies for roles that are
/// superusers or have `BYPASSRLS` — so if the controller connects as
/// such a role, the RFC 0004 org-isolation policies become a no-op and
/// tenants would see each other's data with no error. This is the single
/// highest-impact RLS footgun; [`check_rls_role`] surfaces it at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RlsRoleStatus {
    /// The role is a superuser (bypasses RLS unconditionally).
    pub is_superuser: bool,
    /// The role has the `BYPASSRLS` attribute.
    pub bypass_rls: bool,
}

impl RlsRoleStatus {
    /// True when RLS policies will actually apply to this role's queries.
    #[must_use]
    pub fn rls_enforced(&self) -> bool {
        !self.is_superuser && !self.bypass_rls
    }
}

/// Inspect the connecting role's superuser / `BYPASSRLS` attributes.
///
/// Call at startup and `warn!`/refuse if `!rls_enforced()` *when RLS is
/// expected* (RFC 0004 M4). Cheap — one catalog lookup against
/// `pg_roles` for `current_user`.
pub async fn check_rls_role(pool: &Pool<Postgres>) -> anyhow::Result<RlsRoleStatus> {
    let row: (bool, bool) = sqlx::query_as(
        "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(pool)
    .await
    .context("query current_user RLS attributes")?;
    Ok(RlsRoleStatus {
        is_superuser: row.0,
        bypass_rls: row.1,
    })
}

/// Inspect a named role's superuser / `BYPASSRLS` attributes (returns
/// `None` if the role does not exist). Used by the boot guard to verify
/// the SET-ROLE target (`talos_app`) is correctly configured.
async fn named_role_status(
    pool: &Pool<Postgres>,
    role: &str,
) -> anyhow::Result<Option<RlsRoleStatus>> {
    let row: Option<(bool, bool)> =
        sqlx::query_as("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1")
            .bind(role)
            .fetch_optional(pool)
            .await
            .context("query named role RLS attributes")?;
    Ok(row.map(|(is_superuser, bypass_rls)| RlsRoleStatus {
        is_superuser,
        bypass_rls,
    }))
}

/// Boot-time guard: surface whether the RFC 0004 org-isolation RLS
/// policies will actually enforce. Returns the **base** connection's role
/// status; safe to call before RLS is enabled (it only informs).
///
/// Two modes:
/// * **SET-ROLE mode** (`TALOS_RLS_SET_ROLE` on, RFC 0005 S3): request
///   transactions run as [`RLS_APP_ROLE`] via `SET LOCAL ROLE`, so the
///   base connection may be a superuser and RLS still enforces. The guard
///   instead verifies `talos_app` exists and is non-bypass — and
///   `error!`s if it isn't (that would silently defeat enforcement).
/// * **Direct mode** (default): the base connection's own attributes
///   decide enforcement — warn if it bypasses.
pub async fn warn_if_rls_will_be_bypassed(pool: &Pool<Postgres>) -> RlsRoleStatus {
    let status = match check_rls_role(pool).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "could not determine DB role RLS status");
            // Unknown → assume the worst for visibility, but don't block boot.
            return RlsRoleStatus {
                is_superuser: true,
                bypass_rls: true,
            };
        }
    };

    if rls_set_role_enabled() {
        match named_role_status(pool, RLS_APP_ROLE).await {
            Ok(Some(app)) if app.rls_enforced() => {
                tracing::info!(
                    base_is_superuser = status.is_superuser,
                    "RLS SET-ROLE mode active: request transactions run as `{}` \
                     (non-superuser, no BYPASSRLS) — RLS enforced regardless of the \
                     base connection's privileges.",
                    RLS_APP_ROLE
                );
            }
            Ok(Some(app)) => {
                tracing::error!(
                    is_superuser = app.is_superuser,
                    bypass_rls = app.bypass_rls,
                    "TALOS_RLS_SET_ROLE is on but role `{}` is a superuser or has \
                     BYPASSRLS — RLS would be SILENTLY BYPASSED. Fix the role \
                     attributes (migration 20260529220000_talos_app_role.sql).",
                    RLS_APP_ROLE
                );
            }
            Ok(None) => {
                tracing::error!(
                    "TALOS_RLS_SET_ROLE is on but role `{}` does not exist — scoped \
                     transactions will FAIL. Apply migration \
                     20260529220000_talos_app_role.sql.",
                    RLS_APP_ROLE
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not verify `{}` role attributes", RLS_APP_ROLE);
            }
        }
        return status;
    }

    if !status.rls_enforced() {
        tracing::warn!(
            is_superuser = status.is_superuser,
            bypass_rls = status.bypass_rls,
            "DB role bypasses row-level security — RFC 0004 tenant-isolation \
             policies will be a NO-OP for this connection. Either connect as a \
             non-superuser role WITHOUT BYPASSRLS, or set TALOS_RLS_SET_ROLE=1 to \
             enforce per-transaction via `SET LOCAL ROLE talos_app` (RFC 0005 S3)."
        );
    } else {
        tracing::debug!("DB role enforces RLS (not superuser, no BYPASSRLS)");
    }
    status
}

/// Initialize database connection pool
pub async fn init_pool() -> anyhow::Result<Pool<Postgres>> {
    let _ = dotenvy::dotenv();

    // In production we require an explicit DATABASE_URL; fail fast if it's missing.
    // Load DATABASE_URL or return a clear error instead of panicking.
    let db_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            return Err(anyhow::anyhow!(
                "environment variable DATABASE_URL must be set (Postgres connection string)"
            ));
        }
    };

    // SECURITY: In production, require sslmode in the DATABASE_URL to ensure
    // credentials and data are encrypted in transit. Acceptable values:
    // sslmode=require, sslmode=verify-ca, sslmode=verify-full.
    if talos_config::is_production() && !db_url.contains("sslmode=") {
        tracing::warn!(
            "DATABASE_URL does not contain sslmode parameter. \
             In production, use ?sslmode=require (or verify-ca/verify-full) \
             to encrypt database connections."
        );
    }

    // Connection pool configuration for production workloads
    // 30 connections balances performance with resource usage.
    // MCP-679 (2026-05-13): `=0`-safe env helper. Pre-fix
    // `DB_MAX_CONNECTIONS=0` (helm placeholder pattern) configured
    // sqlx's PgPoolOptions with max=0; combined with min=5 just below,
    // the pool builder fails at startup. Routing through
    // `positive_env_or_default` substitutes the 30 default + emits
    // `event_kind=env_nonpositive_substituted` WARN. Sibling fix-class
    // to the broader `=0` env-var footgun family.
    let max_connections = talos_config::positive_env_or_default::<u32>("DB_MAX_CONNECTIONS", 30);

    // SECURITY: Statement timeout to prevent long-running queries from DoSing the system.
    // Default: 60 seconds for queries, can be overridden via DB_STATEMENT_TIMEOUT_SECS.
    // MCP-679: `=0`-safe env helper. `DB_STATEMENT_TIMEOUT_SECS=0` would
    // emit `SET statement_timeout = '0s'` — in Postgres semantics, 0
    // DISABLES the timeout entirely. Operationally a feature regression
    // (long queries no longer killed = DoS surface), so substitute the
    // 60s default and WARN.
    let statement_timeout_secs =
        talos_config::positive_env_or_default::<u64>("DB_STATEMENT_TIMEOUT_SECS", 60);

    // SECURITY: Execution timeout for complex queries (e.g., report generation)
    // Default: 5 minutes (300 seconds), can be overridden via DB_EXECUTION_TIMEOUT_SECS.
    // MCP-679: `=0`-safe env helper, same rationale as above.
    let execution_timeout_secs =
        talos_config::positive_env_or_default::<u64>("DB_EXECUTION_TIMEOUT_SECS", 300);

    // Apply timeout parameters via SET-on-connect rather than libpq `options=`
    // startup parameters. Neon's pooler (and PgBouncer-fronted setups) reject
    // arbitrary startup options but pass SET commands through to the backend
    // session — see https://neon.tech/docs/connect/connection-errors#unsupported-startup-parameter
    //
    // statement_timeout: terminate queries running longer than this
    // idle_in_transaction_session_timeout: kill idle transactions (connection leaks)
    // application_name: tag connections so DBA tooling can attribute load
    tracing::info!(
        "Connecting to database with statement_timeout={}s, execution_timeout={}s",
        statement_timeout_secs,
        execution_timeout_secs
    );

    PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(5) // Keep minimum connections warm
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(Some(std::time::Duration::from_secs(300))) // 5 minutes
        .test_before_acquire(true)
        .max_lifetime(Some(std::time::Duration::from_secs(1800))) // 30 minutes
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                use sqlx::Executor;
                conn.execute("SET application_name = 'talos_controller'")
                    .await?;
                conn.execute(
                    format!("SET statement_timeout = '{}s'", statement_timeout_secs).as_str(),
                )
                .await?;
                conn.execute("SET idle_in_transaction_session_timeout = '60s'")
                    .await?;
                Ok(())
            })
        })
        .connect(&db_url)
        .await
        .context("Failed to connect to Postgres")
}

/// Initialize an optional read-replica connection pool for query offloading.
///
/// In multi-region deployments, read-heavy queries (analytics, search, listing)
/// can be routed to a read replica to reduce load on the primary.
///
/// Set `DATABASE_READ_REPLICA_URL` to enable. If not set, returns `None` and
/// callers should fall back to the primary pool.
///
/// The replica pool uses the same timeout/pool configuration as the primary but
/// with `test_before_acquire = true` to detect replication lag-induced staleness.
pub async fn init_read_replica_pool() -> Option<Pool<Postgres>> {
    let replica_url = match std::env::var("DATABASE_READ_REPLICA_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => return None,
    };

    // MCP-679: `=0`-safe env helper for the read-replica pool too.
    // Same destructive failure mode as the primary pool — sqlx
    // PgPoolOptions with max=0 + min=2 (set below) fails at startup.
    let max_connections =
        talos_config::positive_env_or_default::<u32>("DB_READ_REPLICA_MAX_CONNECTIONS", 20);

    let statement_timeout_secs =
        talos_config::positive_env_or_default::<u64>("DB_STATEMENT_TIMEOUT_SECS", 60);

    // Same SET-on-connect approach as the primary pool — see the comment in
    // init_pool() for why this avoids libpq `options=` startup parameters.
    match PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .idle_timeout(Some(std::time::Duration::from_secs(300)))
        .test_before_acquire(true)
        .max_lifetime(Some(std::time::Duration::from_secs(1800)))
        .after_connect(move |conn, _meta| {
            Box::pin(async move {
                use sqlx::Executor;
                conn.execute("SET application_name = 'talos_controller_replica'")
                    .await?;
                conn.execute(
                    format!("SET statement_timeout = '{}s'", statement_timeout_secs).as_str(),
                )
                .await?;
                // MCP-1059 (2026-05-15): mirror the primary pool's
                // `idle_in_transaction_session_timeout = 60s` setting.
                // Without it, a replica connection that BEGINs a
                // transaction and then idles (caller dropped, future
                // cancelled, request handler stalled) leaks the
                // connection for the full pool lifetime. The replica
                // ought to be read-only and short-lived in practice,
                // but defense-in-depth matches the primary so any
                // future code path (sqlx BEGIN/ROLLBACK on the read
                // pool, manual `start_transaction` from analytics) is
                // covered by the same safety net as the primary.
                conn.execute("SET idle_in_transaction_session_timeout = '60s'")
                    .await?;
                conn.execute("SET default_transaction_read_only = on")
                    .await?;
                Ok(())
            })
        })
        .connect(&replica_url)
        .await
    {
        Ok(pool) => {
            tracing::info!(
                max_connections = max_connections,
                "Read replica pool initialized"
            );
            Some(pool)
        }
        Err(e) => {
            tracing::error!(
                "Failed to connect to read replica: {} — queries will use primary",
                e
            );
            None
        }
    }
}


#[cfg(test)]
mod rls_role_prefix_tests {
    use super::*;

    #[test]
    fn prefix_is_set_role_when_enabled() {
        // Locks the exact SQL + role name: a drift here would silently
        // stop RLS from being activated (enabled) or break the
        // single-round-trip concatenation.
        assert_eq!(rls_role_prefix_for(true), "SET LOCAL ROLE talos_app; ");
        assert!(rls_role_prefix_for(true).ends_with("; "));
        assert!(rls_role_prefix_for(true).contains(RLS_APP_ROLE));
    }

    #[test]
    fn prefix_is_empty_when_disabled() {
        // Default-OFF must be byte-identical to the pre-S3 behavior.
        assert_eq!(rls_role_prefix_for(false), "");
    }
}
