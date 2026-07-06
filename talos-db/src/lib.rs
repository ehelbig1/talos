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

/// A **request-scoped unit of work** (RFC 0005 S3): ONE tenant-scoped
/// transaction that every data-access call in a request shares, so the
/// role + GUC are set **once** (not once per repository method) and all
/// of the request's queries see a single, consistent tenant snapshot.
///
/// This replaces the "open a fresh `begin_tenant_read_scoped` per
/// repository method" shape — a request making N data calls otherwise
/// pays N `BEGIN`/`SET LOCAL`/`COMMIT` round-trips across N independent
/// transactions.
///
/// **Executor-threading convention:** data-access functions should accept
/// `&mut sqlx::PgConnection` (what [`conn`](Self::conn) yields) rather
/// than reaching for `&self.db_pool`. The same function then composes
/// into a unit of work *or* runs standalone on a pooled connection (a
/// `Transaction` derefs to `PgConnection`, and so does an acquired pool
/// connection), so the repository layer migrates incrementally without a
/// second set of methods.
///
/// `SET LOCAL ROLE` + the GUCs are transaction-scoped, so they reset when
/// the unit of work is committed **or dropped** — no pooled-connection
/// leakage. The caller MUST call [`commit`](Self::commit); dropping rolls
/// back (correct for read-only flows, and fail-safe for writes).
pub struct UnitOfWork<'a> {
    tx: Transaction<'a, Postgres>,
}

impl<'a> UnitOfWork<'a> {
    /// Begin a unit of work carrying the membership-union read backstop
    /// (same scoping + `SET LOCAL ROLE` semantics as
    /// [`begin_tenant_read_scoped`]). Pass the user's accessible org ids
    /// in the scope so org-shared rows remain visible.
    pub async fn begin(pool: &'a Pool<Postgres>, scope: &TenantReadScope) -> anyhow::Result<Self> {
        Ok(Self {
            tx: begin_tenant_read_scoped(pool, scope).await?,
        })
    }

    /// Convenience for a **personal** (per-user) unit of work — sets
    /// `app.current_user_id` with an empty org list, so the RLS policy's
    /// `user_id = current_user_id` clause matches. Use [`begin`](Self::begin)
    /// with the user's accessible orgs for org-shared reads.
    pub async fn begin_user(pool: &'a Pool<Postgres>, user_id: uuid::Uuid) -> anyhow::Result<Self> {
        Self::begin(pool, &TenantReadScope::new(user_id, Vec::new())).await
    }

    /// The shared executor for data-access calls within this unit of work.
    /// Pass it where a function/repository method takes
    /// `&mut sqlx::PgConnection`. Each call reborrows, so successive calls
    /// compose naturally:
    /// `let a = foo(uow.conn()).await?; let b = bar(uow.conn()).await?;`
    pub fn conn(&mut self) -> &mut sqlx::PgConnection {
        // Transaction<Postgres> derefs to the underlying PgConnection.
        &mut self.tx
    }

    /// Commit the unit of work (resets the role + GUCs).
    pub async fn commit(self) -> anyhow::Result<()> {
        self.tx.commit().await.context("commit unit of work")?;
        Ok(())
    }
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
    let row: (bool, bool) =
        sqlx::query_as("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
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

/// Whether tenant-isolation RLS will *actually* enforce for request-path
/// queries against this pool, resolving BOTH modes:
///
/// * **SET-ROLE mode** (`TALOS_RLS_SET_ROLE` on): enforcement depends on the
///   `talos_app` role existing and being non-superuser / non-`BYPASSRLS` — the
///   base connection's own privileges are irrelevant because every scoped tx
///   runs `SET LOCAL ROLE talos_app`.
/// * **Direct mode** (default): enforcement depends on the base connection's
///   own role attributes.
///
/// Returns `Ok(false)` (not an error) when the configuration is valid but
/// simply won't enforce — that's the case the production guard turns into a
/// refusal. Propagates only genuine catalog-query errors.
pub async fn rls_enforcement_effective(pool: &Pool<Postgres>) -> anyhow::Result<bool> {
    if rls_set_role_enabled() {
        // Enforcement rides on `talos_app`; the base role may be a superuser.
        return Ok(matches!(
            named_role_status(pool, RLS_APP_ROLE).await?,
            Some(app) if app.rls_enforced()
        ));
    }
    Ok(check_rls_role(pool).await?.rls_enforced())
}

/// Pure parse of a boolean opt-in flag value (`1` / `true` / `yes` / `on`,
/// case-insensitive, surrounding whitespace ignored). `None` (unset) → `false`.
/// Split out so the accept/reject logic is unit-tested without touching process
/// env (which is global mutable state and racy across parallel tests).
fn parse_opt_in(value: Option<&str>) -> bool {
    match value {
        Some(v) => {
            let v = v.trim();
            v.eq_ignore_ascii_case("true")
                || v == "1"
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("on")
        }
        None => false,
    }
}

/// Parse a boolean opt-in env var (`1` / `true` / `yes` / `on`, case-insensitive).
fn env_opt_in(var: &str) -> bool {
    parse_opt_in(std::env::var(var).ok().as_deref())
}

/// Production fail-closed RLS posture guard (RFC 0004 / RFC 0005 S3).
///
/// Mirrors the env-KEK production guard (`controller/src/main.rs`,
/// `prod-kek-guard`): in production, refuse to boot when tenant-isolation RLS
/// would silently be a no-op — UNLESS the operator explicitly acknowledges the
/// weaker posture via `TALOS_ALLOW_RLS_DISABLED=1`.
///
/// Before this guard, RLS shipped OFF by default (`TALOS_RLS_SET_ROLE` unset)
/// and the misconfiguration only produced a `warn!` that scrolled past in logs,
/// leaving cross-tenant isolation resting entirely on app-layer query
/// discipline. The guard makes "isolation is actually enforced" a boot
/// precondition in production while keeping dev/test frictionless (the guard is
/// a no-op when `is_production` is false).
///
/// The override is loud + SIEM-greppable (`target: "talos_security"`,
/// `event_kind = "rls_disabled_in_production"`) so a homelab/single-tenant
/// operator who legitimately runs without RLS is visible in audit, not silent.
pub async fn enforce_production_rls_posture(
    pool: &Pool<Postgres>,
    is_production: bool,
) -> anyhow::Result<()> {
    if !is_production {
        return Ok(());
    }
    // Catalog errors are non-fatal for the guard itself: if we cannot read
    // pg_roles we cannot prove enforcement, but blocking boot on a transient
    // catalog hiccup is worse than the warn that `warn_if_rls_will_be_bypassed`
    // already emitted. Treat an error as "cannot confirm" and fall through to
    // the opt-in check rather than hard-failing on infrastructure flakiness.
    let effective = match rls_enforcement_effective(pool).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "RLS posture guard: could not determine enforcement status");
            false
        }
    };
    if effective {
        return Ok(());
    }

    if env_opt_in("TALOS_ALLOW_RLS_DISABLED") {
        tracing::error!(
            target: "talos_security",
            event_kind = "rls_disabled_in_production",
            set_role_mode = rls_set_role_enabled(),
            "Row-level tenant isolation is NOT enforced in production, accepted via \
             TALOS_ALLOW_RLS_DISABLED. Cross-tenant isolation rests entirely on \
             app-layer query scoping (OrgScope/TenantReadScope). Provision the \
             `talos_app` role + set TALOS_RLS_SET_ROLE=1 (or connect as a \
             non-superuser role) for a defence-in-depth posture."
        );
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "Row-level security would be a NO-OP in production — refusing to boot. \
         RFC 0004 tenant-isolation policies do not enforce because {}. Fix by one \
         of: (a) set TALOS_RLS_SET_ROLE=1 AND apply migration \
         20260529220000_talos_app_role.sql so request transactions run as the \
         non-bypass `talos_app` role; (b) connect the controller as a \
         non-superuser role without BYPASSRLS. To run WITHOUT row-level isolation \
         anyway (e.g. a single-tenant homelab), set TALOS_ALLOW_RLS_DISABLED=1 to \
         acknowledge that cross-tenant isolation then rests solely on app-layer \
         query scoping.",
        if rls_set_role_enabled() {
            "TALOS_RLS_SET_ROLE is on but the `talos_app` role is missing, a \
             superuser, or has BYPASSRLS"
        } else {
            "TALOS_RLS_SET_ROLE is off and the connecting role is a superuser or \
             has BYPASSRLS"
        }
    ))
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

    // SECURITY: In production, REFUSE to start unless the DATABASE_URL pins a
    // TLS-guaranteeing sslmode. Absent / `disable` / `allow` / `prefer` all
    // permit a cleartext connection (`prefer` only *opportunistically* uses
    // TLS), leaving credentials and ePHI on the wire — a transmission-security
    // violation (HIPAA §164.312(e) / SOC2 CC6.7). Only require / verify-ca /
    // verify-full guarantee encryption.
    // tls-prod-gate-postgres
    if talos_config::is_production() && !db_url_tls_guaranteed(&db_url) {
        return Err(anyhow::anyhow!(
            "DATABASE_URL must set sslmode=require (or verify-ca / verify-full) in \
             production — refusing to start. sslmode absent/disable/allow/prefer does \
             not guarantee TLS, leaving credentials and data in cleartext on the wire."
        ));
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

/// Try to take a SESSION-level Postgres advisory lock on the given
/// connection. Session locks persist until explicitly unlocked or the
/// Postgres session ends — callers MUST release via
/// `release_advisory_lock` on the SAME connection (see its doc for the
/// pool-reuse leak this pairing prevents).
pub async fn try_advisory_lock(
    conn: &mut sqlx::PgConnection,
    lock_id: i64,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)")
        .bind(lock_id)
        .fetch_one(conn)
        .await
}

/// Release a session-level advisory lock taken via `try_advisory_lock`.
///
/// MCP-702: takes the `PoolConnection` BY VALUE so it can `detach()` on
/// unlock failure. sqlx pool connections are NOT closed on drop — they
/// return to the pool with the Postgres session (and any session-level
/// advisory locks) intact, so a failed `pg_advisory_unlock` would leak
/// the lock to the next pool consumer and stall future
/// `pg_advisory_xact_lock(same_key)` attempts indefinitely. Detaching
/// converts the connection into a raw `PgConnection` that closes on
/// Drop, ending the session and freeing the lock server-side.
///
/// **Remaining caller-side hazard**: a task panic between the lock
/// acquisition and this call drops the PoolConnection without unlocking
/// (the lock leaks until pool idle-reaping). Wrap critical sections in
/// an inner `async {}` block and call this in the outer scope
/// regardless of the inner Result (MCP-701 IIFE pattern) where
/// practical.
pub async fn release_advisory_lock(
    mut conn: sqlx::pool::PoolConnection<sqlx::Postgres>,
    lock_id: i64,
) {
    match sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(lock_id)
        .execute(&mut *conn)
        .await
    {
        Ok(_) => {
            // Happy path — lock released, conn returns to pool on drop.
        }
        Err(e) => {
            tracing::warn!(
                lock_id,
                error = %e,
                "Failed to release pg advisory lock — detaching connection from pool \
                 so the lock doesn't leak to the next consumer"
            );
            // Force-close the underlying connection so the session ends
            // and Postgres releases all advisory locks held by it.
            let _detached = conn.detach();
        }
    }
}

/// Returns `true` when `db_url` pins an sslmode that GUARANTEES a TLS
/// connection: `require`, `verify-ca`, or `verify-full`. Returns `false` for an
/// absent sslmode or the non-guaranteeing modes (`disable`, `allow`, `prefer` —
/// `prefer` only opportunistically negotiates TLS and silently falls back to
/// cleartext). Pure so the production boot gate's accept/reject logic is
/// unit-tested without env or a live DB. See `tls-prod-gate-postgres`.
fn db_url_tls_guaranteed(db_url: &str) -> bool {
    db_url.contains("sslmode=require")
        || db_url.contains("sslmode=verify-ca")
        || db_url.contains("sslmode=verify-full")
}

#[cfg(test)]
mod db_url_tls_gate_tests {
    use super::db_url_tls_guaranteed;

    #[test]
    fn accepts_tls_guaranteeing_modes() {
        for m in ["require", "verify-ca", "verify-full"] {
            let url = format!("postgres://u:p@host/db?sslmode={m}");
            assert!(db_url_tls_guaranteed(&url), "should accept sslmode={m}");
        }
    }

    #[test]
    fn rejects_absent_and_non_guaranteeing_modes() {
        // Absent entirely → cleartext-capable.
        assert!(!db_url_tls_guaranteed("postgres://u:p@host/db"));
        // Modes that permit (or silently fall back to) cleartext.
        for m in ["disable", "allow", "prefer"] {
            let url = format!("postgres://u:p@host/db?sslmode={m}");
            assert!(!db_url_tls_guaranteed(&url), "must reject sslmode={m}");
        }
    }

    #[test]
    fn accepts_tls_mode_among_other_params() {
        let url =
            "postgres://u:p@host/db?connect_timeout=5&sslmode=verify-full&application_name=talos";
        assert!(db_url_tls_guaranteed(url));
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

#[cfg(test)]
mod rls_prod_guard_tests {
    use super::{enforce_production_rls_posture, parse_opt_in};
    use sqlx::postgres::PgPoolOptions;

    #[test]
    fn opt_in_accepts_truthy_forms() {
        for v in ["1", "true", "TRUE", "yes", "On", " true ", "\ton\n"] {
            assert!(parse_opt_in(Some(v)), "should accept {v:?}");
        }
    }

    #[test]
    fn opt_in_rejects_falsy_and_unset() {
        assert!(!parse_opt_in(None));
        for v in ["", "0", "false", "no", "off", "enabled", "2", "y"] {
            assert!(!parse_opt_in(Some(v)), "should reject {v:?}");
        }
    }

    #[tokio::test]
    async fn guard_is_noop_outside_production() {
        // is_production=false must return Ok WITHOUT touching the pool — a
        // lazy pool to a bogus URL proves no query is issued (connecting would
        // error). The guard must short-circuit before any catalog lookup so
        // dev/test boots are never gated on RLS.
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://nonexistent:5432/none")
            .expect("connect_lazy never dials");
        enforce_production_rls_posture(&pool, false)
            .await
            .expect("non-production must be a no-op");
    }
}
