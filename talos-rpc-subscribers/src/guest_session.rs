//! The pooled connection one guest SQL query runs on, and the rule for
//! handing it back.
//!
//! # Why this exists
//!
//! `execute_guest_query` runs caller-authored SQL inside `BEGIN … COMMIT` on
//! the controller's SHARED app pool. The transaction boundary clears
//! `SET LOCAL` state, but not everything a statement can leave on a Postgres
//! SESSION: a session-level advisory lock (`SELECT pg_advisory_lock(k)`)
//! survives COMMIT and ROLLBACK alike. Before this module the connection went
//! back to the pool still holding it, for the rest of that connection's life
//! (up to the pool's 30-minute `max_lifetime`), and the controller takes its
//! own advisory locks on the same pool — budget admission, secret upsert, the
//! Google Calendar fleet lock. A guest whose key collided with one of those
//! blocked it; a guest that simply locked could pin connections.
//!
//! The expression deny-list (`talos_workflow_job_protocol::
//! is_disallowed_sql_function`, the `pg_advisory_` / `pg_try_advisory_`
//! families) now refuses the call at parse time on both fences, and migration
//! `20260925160000` revokes EXECUTE from PUBLIC. This module is the third
//! layer and the only one that does not depend on recognising the call: it
//! guarantees that no connection a guest query touched returns to the pool
//! with a session-level advisory lock held.
//!
//! # The rule
//!
//! [`GuestSession::release`] is the ONLY path back to the pool, and it runs
//! [`GUEST_SESSION_UNLOCK_SQL`] first. Every other exit — the query budget
//! elapsed mid-statement (the connection's protocol state is unknown), the
//! unlock itself failed, a panic, or the caller's future being dropped —
//! reaches [`Drop`], which DETACHES the connection so it closes instead of
//! being reused. Postgres releases every session lock when a session ends.
//!
//! `DISCARD ALL` is deliberately NOT used: it would also drop sqlx's cached
//! prepared statements on the connection, so every later query on it would
//! re-prepare against a statement cache that still names them.
//!
//! Large objects are NOT cleaned up here and cannot be: an `lo_open`
//! descriptor already closes at transaction end, and an object a guest
//! created (`lo_create`, `lo_from_bytea`) is a row in `pg_largeobject`, not
//! session state — disconnecting does not remove it. That family is closed by
//! the deny-list and the REVOKE only.

use sqlx::pool::PoolConnection;
use sqlx::Postgres;

/// The backstop. Releases every SESSION-level advisory lock the connection
/// holds, shared and exclusive; transaction-level ones are already gone by the
/// time it runs. Runs as the session (app) role, outside any transaction.
pub(crate) const GUEST_SESSION_UNLOCK_SQL: &str = "SELECT pg_advisory_unlock_all()";

/// How long the unlock may take before the connection is detached instead.
/// Not charged to the guest's query budget: it runs after the guest's
/// transaction has already ended, and a slow unlock costs a closed connection,
/// never a wrong answer.
pub(crate) const GUEST_SESSION_RELEASE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(5);

/// Why a connection did not go back to the pool. Carried into the log line
/// only; the guest's own result is unaffected (see `execute_guest_query`).
#[derive(Debug)]
pub(crate) enum ReleaseFailure {
    /// `pg_advisory_unlock_all()` returned an error.
    Unlock(sqlx::Error),
    /// The unlock did not answer within [`GUEST_SESSION_RELEASE_TIMEOUT`].
    TimedOut,
}

impl std::fmt::Display for ReleaseFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unlock(e) => write!(f, "advisory unlock failed: {e}"),
            Self::TimedOut => write!(
                f,
                "advisory unlock did not answer within {}s",
                GUEST_SESSION_RELEASE_TIMEOUT.as_secs()
            ),
        }
    }
}

/// Owns the pooled connection a guest query runs on. See the module docs:
/// dropping one without [`GuestSession::release`] closes the connection.
pub(crate) struct GuestSession {
    conn: Option<PoolConnection<Postgres>>,
}

impl GuestSession {
    pub(crate) fn new(conn: PoolConnection<Postgres>) -> Self {
        Self { conn: Some(conn) }
    }

    /// The connection, for the guest's transaction. `None` only after
    /// `release` has consumed the session, which cannot be observed from
    /// outside because `release` takes `self`.
    pub(crate) fn connection(&mut self) -> Option<&mut sqlx::PgConnection> {
        self.conn.as_deref_mut()
    }

    /// Clear session-level advisory locks, then return the connection to the
    /// pool. On any failure — including this future being dropped while the
    /// unlock is in flight, because the connection stays inside `self` until
    /// the unlock has answered — the connection is detached instead.
    pub(crate) async fn release(mut self) -> Result<(), ReleaseFailure> {
        let Some(conn) = self.conn.as_deref_mut() else {
            return Ok(());
        };
        let unlocked = tokio::time::timeout(
            GUEST_SESSION_RELEASE_TIMEOUT,
            sqlx::query(GUEST_SESSION_UNLOCK_SQL).execute(conn),
        )
        .await;
        match unlocked {
            Ok(Ok(_)) => {
                // The one path back to the pool.
                drop(self.conn.take());
                Ok(())
            }
            // `self` drops on return with the connection still inside it,
            // so `Drop` detaches it.
            Ok(Err(e)) => Err(ReleaseFailure::Unlock(e)),
            Err(_) => Err(ReleaseFailure::TimedOut),
        }
    }
}

impl Drop for GuestSession {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            // The session's state is unknown: it may be mid-statement (the
            // budget elapsed), or its advisory locks could not be cleared.
            // Detaching takes it out of the pool's accounting and dropping the
            // raw connection closes the socket; Postgres ends the backend —
            // and releases every session lock it held — once it notices,
            // which for a backend still executing is when its statement ends
            // (bounded by the pool's `statement_timeout`).
            drop(conn.detach());
        }
    }
}

/// Real-Postgres coverage for `execute_guest_query`'s session backstop and
/// for migration `20260925160000`'s privilege change. Gated on
/// `TALOS_TEST_DATABASE_URL` pointing at a MIGRATED database; named
/// explicitly in `scripts/test-integration.sh`, because a gated test nobody
/// names is a green skip.
///
/// `execute_guest_query` is called directly, past both deny-lists, on
/// purpose: the unlock is the layer that must hold when recognition fails, so
/// it is tested with the call recognition would have refused.
#[cfg(test)]
mod db_tests {
    use crate::execute_guest_query_within;
    use sqlx::postgres::PgPoolOptions;
    use sqlx::{Connection, PgConnection, PgPool};
    use std::time::Duration;
    use talos_memory::database_rpc::DatabaseRpcError;

    fn database_url() -> Option<String> {
        std::env::var("TALOS_TEST_DATABASE_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
    }

    /// ONE connection, so every guest query in a test runs on the same
    /// backend unless the backstop detached it — which the backend pid makes
    /// observable.
    async fn single_connection_pool(url: &str) -> PgPool {
        PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(10))
            .connect(url)
            .await
            .expect("connect single-connection pool")
    }

    /// A key no other test (or other binary sharing the migrated database)
    /// will pick. Kept below 2^31 so `pg_locks` shows it as `classid = 0,
    /// objid = key`.
    fn unique_key() -> i64 {
        i64::from(uuid::Uuid::new_v4().as_u128() as u32 & 0x7fff_ffff) | 1
    }

    /// Advisory locks on `key` held by ANY session, read from a SEPARATE
    /// connection (the pool's only connection is the one under test).
    async fn advisory_locks_on(observer: &mut PgConnection, key: i64) -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM pg_locks \
             WHERE locktype = 'advisory' AND classid = 0 AND objid = $1::bigint::oid \
               AND objsubid = 1 \
               AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
        )
        .bind(key)
        .fetch_one(observer)
        .await
        .expect("read pg_locks")
    }

    /// The backend pid of the pool's connection, read THROUGH the guest path
    /// so the read itself goes through acquire → release.
    async fn guest_backend_pid(pool: &PgPool) -> i64 {
        let res = execute_guest_query_within(
            pool,
            "SELECT pg_backend_pid() AS pid",
            &[],
            true,
            None,
            Duration::from_secs(10),
        )
        .await
        .expect("read backend pid through the guest path");
        let rows: serde_json::Value = serde_json::from_str(&res.rows_json).expect("rows json");
        rows[0]["pid"].as_i64().expect("pid column")
    }

    /// A session lock taken by a SUCCESSFUL guest statement must be gone when
    /// the call returns, and the connection must have been REUSED — i.e. the
    /// unlock ran, rather than the detach fallback closing the session. The
    /// pid equality is what separates the two: both leave `pg_locks` empty.
    #[tokio::test]
    async fn a_session_advisory_lock_does_not_outlive_a_successful_guest_query() {
        let Some(url) = database_url() else { return };
        let pool = single_connection_pool(&url).await;
        let mut observer = PgConnection::connect(&url).await.expect("observer");
        let key = unique_key();

        let pid_before = guest_backend_pid(&pool).await;
        for is_fetch in [true, false] {
            let res = execute_guest_query_within(
                &pool,
                &format!("SELECT pg_advisory_lock({key})"),
                &[],
                is_fetch,
                None,
                Duration::from_secs(10),
            )
            .await;
            assert!(res.is_ok(), "the lock statement itself succeeds: {res:?}");
            assert_eq!(
                advisory_locks_on(&mut observer, key).await,
                0,
                "a session advisory lock survived the guest query (is_fetch={is_fetch}) — \
                 the pooled connection went back holding it"
            );
        }
        assert_eq!(
            guest_backend_pid(&pool).await,
            pid_before,
            "the connection must be REUSED after a clean unlock, not closed"
        );
    }

    /// The error path: the lock is taken, THEN the statement fails, so the
    /// transaction rolls back — and a session lock survives ROLLBACK. The pid
    /// equality proves the unlock ran after sqlx's queued ROLLBACK (had it run
    /// inside the aborted transaction it would fail with 25P02 and the session
    /// would be detached).
    ///
    /// The divisor is VOLATILE on purpose. A literal `1/0` is constant-folded
    /// at PLAN time, so the statement errors before `pg_advisory_lock` runs
    /// and the test would pass over a lock that was never taken — measured:
    /// `SELECT pg_advisory_lock(k), 1/0` leaves 0 locks, the volatile form 1.
    #[tokio::test]
    async fn a_session_advisory_lock_does_not_outlive_a_failed_guest_query() {
        let Some(url) = database_url() else { return };
        let pool = single_connection_pool(&url).await;
        let mut observer = PgConnection::connect(&url).await.expect("observer");
        let key = unique_key();

        let pid_before = guest_backend_pid(&pool).await;
        for is_fetch in [true, false] {
            let res = execute_guest_query_within(
                &pool,
                &format!("SELECT pg_advisory_lock({key}), 1/(random() * 0)::int"),
                &[],
                is_fetch,
                None,
                Duration::from_secs(10),
            )
            .await;
            assert!(
                matches!(res, Err(DatabaseRpcError::QueryError(_))),
                "division by zero must surface as a query error: {res:?}"
            );
            assert_eq!(
                advisory_locks_on(&mut observer, key).await,
                0,
                "a session advisory lock survived a FAILED guest query (is_fetch={is_fetch})"
            );
        }
        assert_eq!(
            guest_backend_pid(&pool).await,
            pid_before,
            "the unlock must succeed after the rollback, so the connection is reused"
        );
    }

    /// The budget elapsed mid-statement: the connection's protocol state is
    /// unknown, so it must be detached, never returned. The lock is released
    /// when the backend's statement ends and it finds the socket closed, so
    /// this polls; the pid then differs because the pool had to open a new
    /// connection — which it could only do because the detached one left the
    /// pool's accounting (with `max_connections(1)` a leaked slot would make
    /// the next acquire time out).
    #[tokio::test]
    async fn a_timed_out_guest_query_closes_its_connection() {
        let Some(url) = database_url() else { return };
        let pool = single_connection_pool(&url).await;
        let mut observer = PgConnection::connect(&url).await.expect("observer");
        let key = unique_key();

        let pid_before = guest_backend_pid(&pool).await;
        let res = execute_guest_query_within(
            &pool,
            &format!("SELECT pg_advisory_lock({key}), pg_sleep(3)"),
            &[],
            false,
            None,
            Duration::from_secs(1),
        )
        .await;
        assert!(
            matches!(res, Err(DatabaseRpcError::Timeout)),
            "a statement past its budget must time out: {res:?}"
        );

        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if advisory_locks_on(&mut observer, key).await == 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the timed-out session still holds its advisory lock 20s later — \
                 the connection was not closed"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert_ne!(
            guest_backend_pid(&pool).await,
            pid_before,
            "a timed-out connection must be detached, not returned to the pool"
        );
    }

    /// Migration `20260925160000`: `talos_guest` holds EXECUTE on none of the
    /// two families, PUBLIC holds it on none, and the roles the controller
    /// itself runs as keep it (its own `pg_advisory_xact_lock` callers run as
    /// `talos_app` inside `begin_*_scoped` transactions when
    /// `TALOS_RLS_SET_ROLE` is on). The population is read from the server, so
    /// a family member the pinned protocol-crate list does not name is still
    /// checked here.
    #[tokio::test]
    async fn the_guest_role_cannot_execute_either_family() {
        let Some(url) = database_url() else { return };
        let mut conn = PgConnection::connect(&url).await.expect("connect");

        let family: Vec<(String, bool, bool, bool, bool)> = sqlx::query_as(
            "SELECT p.oid::regprocedure::text, \
                    has_function_privilege('talos_guest', p.oid, 'EXECUTE'), \
                    EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a \
                             WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'), \
                    has_function_privilege(current_user, p.oid, 'EXECUTE'), \
                    has_function_privilege('talos_app', p.oid, 'EXECUTE') \
               FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
              WHERE n.nspname = 'pg_catalog' \
                AND (p.proname LIKE 'pg\\_advisory\\_%' OR p.proname LIKE 'pg\\_try\\_advisory\\_%' \
                     OR p.proname LIKE 'lo\\_%' OR p.proname IN ('loread', 'lowrite')) \
              ORDER BY 1",
        )
        .fetch_all(&mut conn)
        .await
        .expect("read family privileges");
        assert!(
            family.len() >= 41,
            "expected the PG17 population of 41 overloads, read {} — is this database migrated?",
            family.len()
        );
        for (sig, guest, public, current, app) in &family {
            assert!(!guest, "talos_guest can still EXECUTE {sig}");
            assert!(!public, "PUBLIC still holds EXECUTE on {sig}");
            // lo_import / lo_export never had a PUBLIC grant: the migration
            // restores what PUBLIC HAD, so talos_app must NOT gain them.
            let owner_only = sig.starts_with("lo_import(") || sig.starts_with("lo_export(");
            assert!(*current, "the migrating role lost EXECUTE on {sig}");
            if owner_only {
                assert!(!app, "talos_app GAINED server-file I/O via {sig}");
            } else {
                assert!(*app, "talos_app lost EXECUTE on {sig}");
            }
        }
        for sig in [
            "pg_advisory_lock(bigint)",
            "pg_advisory_unlock_all()",
            "lo_create(oid)",
        ] {
            let guest: bool = sqlx::query_scalar(
                "SELECT has_function_privilege('talos_guest', $1::regprocedure, 'EXECUTE')",
            )
            .bind(sig)
            .fetch_one(&mut conn)
            .await
            .expect("has_function_privilege");
            assert!(!guest, "talos_guest can EXECUTE {sig}");
        }
    }

    /// The REVOKE is effective on the real guest path: with the guest role
    /// fence on, the lock statement is refused by Postgres itself, and nothing
    /// is held afterwards.
    #[tokio::test]
    async fn the_guest_role_is_refused_the_lock_on_the_real_path() {
        let Some(url) = database_url() else { return };
        let pool = single_connection_pool(&url).await;
        let mut observer = PgConnection::connect(&url).await.expect("observer");
        let key = unique_key();

        let res = execute_guest_query_within(
            &pool,
            &format!("SELECT pg_advisory_lock({key})"),
            &[],
            false,
            Some("talos_guest"),
            Duration::from_secs(10),
        )
        .await;
        match res {
            Err(DatabaseRpcError::QueryError(msg)) => assert!(
                msg.contains("permission denied"),
                "expected a privilege refusal, got {msg}"
            ),
            other => panic!("talos_guest must be refused pg_advisory_lock, got {other:?}"),
        }
        assert_eq!(advisory_locks_on(&mut observer, key).await, 0);
        // Control: the fence itself works for an ordinary statement.
        let ok = execute_guest_query_within(
            &pool,
            "SELECT 1 AS n",
            &[],
            true,
            Some("talos_guest"),
            Duration::from_secs(10),
        )
        .await;
        assert!(ok.is_ok(), "an ordinary statement under the fence: {ok:?}");
    }
}
