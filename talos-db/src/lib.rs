// MCP-953 (2026-05-15): Dead `WorkflowRecord` struct + duplicate
// `get_workflow` helper removed — the canonical pair lives in
// `talos-workflow-repository::WorkflowRecord` / `WorkflowRepository::
// get_workflow` and is what every caller actually uses. The bare
// `talos-db` helpers had no callers (the deferred read-replica wire-in
// `init_read_replica_pool` is still kept below for the operator hook).
use anyhow::Context;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres, Transaction};
use talos_tenancy::OrgScope;

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
    // interpolates a `Uuid` (no caller text, no injection surface).
    sqlx::query(&scope.set_local_org_sql())
        .execute(&mut *tx)
        .await
        .context("set app.current_org_id for tenant scope")?;
    Ok(tx)
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

