//! Boot-time migration runner.
//!
//! Migrations used to run on an ordinary pool connection, which carries the
//! pool's `statement_timeout` (60 s) and no `lock_timeout`. Two defects
//! followed: a migration rewriting a large table was killed at 60 s on every
//! boot, and a migration waiting on a lock held by live traffic queued behind
//! it — and every query on that table queued behind the migration — with no
//! bound but the statement timeout.
//!
//! Now migrations run on a DEDICATED connection that is detached from the
//! pool (so its session settings can never leak into request traffic) with:
//! * `lock_timeout = MIGRATION_LOCK_TIMEOUT` — a migration that cannot get
//!   its lock gives up fast instead of stalling the table; sqlx runs each
//!   migration in its own transaction, so the attempt rolls back cleanly and
//!   is retried up to `MIGRATION_LOCK_ATTEMPTS` times with a short backoff.
//!   The same bound covers sqlx's migration advisory lock, so a replica that
//!   boots while another is migrating waits out the retries rather than
//!   forever.
//! * `statement_timeout = MIGRATION_STATEMENT_TIMEOUT` — long enough for a
//!   table rewrite, still bounded.

use anyhow::Context;
use sqlx::migrate::{MigrateError, Migrator};
use sqlx::{Executor, Pool, Postgres};
use std::time::Duration;

/// Longest a migration statement may wait for a lock before the attempt is
/// abandoned (and retried).
pub const MIGRATION_LOCK_TIMEOUT: &str = "5s";
/// Upper bound on any single migration statement.
pub const MIGRATION_STATEMENT_TIMEOUT: &str = "30min";
/// Total attempts when the only failure is a lock timeout.
pub const MIGRATION_LOCK_ATTEMPTS: u32 = 6;

/// SQLSTATE `lock_not_available` — what `lock_timeout` raises.
const LOCK_NOT_AVAILABLE: &str = "55P03";

/// Whether a failed attempt should be retried: only a lock timeout, and only
/// while attempts remain. Anything else (a syntax error, a checksum
/// mismatch) will fail identically on retry.
#[must_use]
pub fn should_retry(sqlstate: Option<&str>, attempt: u32) -> bool {
    sqlstate == Some(LOCK_NOT_AVAILABLE) && attempt < MIGRATION_LOCK_ATTEMPTS
}

/// Backoff before retry `attempt` (1-based): 2 s, 4 s, 6 s … capped at 10 s.
#[must_use]
pub fn retry_delay(attempt: u32) -> Duration {
    Duration::from_secs(u64::from(attempt.saturating_mul(2)).min(10))
}

fn sqlstate(e: &MigrateError) -> Option<String> {
    match e {
        MigrateError::Execute(sqlx::Error::Database(db))
        | MigrateError::ExecuteMigration(sqlx::Error::Database(db), _) => {
            db.code().map(|c| c.into_owned())
        }
        _ => None,
    }
}

/// Run `migrator` against `pool` on a dedicated, detached connection with a
/// bounded `lock_timeout` and a migration-sized `statement_timeout`.
pub async fn run_migrations(pool: &Pool<Postgres>, migrator: &Migrator) -> anyhow::Result<()> {
    let mut attempt = 1;
    loop {
        // Detached: this connection is closed after use, never returned to
        // the pool with migration-only session settings.
        let mut conn = pool
            .acquire()
            .await
            .context("acquire migration connection")?
            .detach();
        conn.execute(format!("SET lock_timeout = '{MIGRATION_LOCK_TIMEOUT}'").as_str())
            .await
            .context("SET lock_timeout")?;
        conn.execute(format!("SET statement_timeout = '{MIGRATION_STATEMENT_TIMEOUT}'").as_str())
            .await
            .context("SET statement_timeout")?;
        let result = migrator.run(&mut conn).await;
        // Best-effort close; a failure here only leaks one server session
        // until the server notices the socket is gone.
        let _ = sqlx::Connection::close(conn).await;
        match result {
            Ok(()) => return Ok(()),
            Err(e) => {
                let code = sqlstate(&e);
                if !should_retry(code.as_deref(), attempt) {
                    return Err(anyhow::anyhow!(e));
                }
                let delay = retry_delay(attempt);
                tracing::warn!(
                    attempt,
                    max_attempts = MIGRATION_LOCK_ATTEMPTS,
                    delay_ms = delay.as_millis() as u64,
                    "migration could not acquire a lock within {MIGRATION_LOCK_TIMEOUT}; retrying"
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_lock_timeout_is_retried_and_only_while_attempts_remain() {
        assert!(should_retry(Some("55P03"), 1));
        assert!(should_retry(Some("55P03"), MIGRATION_LOCK_ATTEMPTS - 1));
        assert!(!should_retry(Some("55P03"), MIGRATION_LOCK_ATTEMPTS));
        // statement_timeout (57014), syntax errors, no SQLSTATE: never.
        assert!(!should_retry(Some("57014"), 1));
        assert!(!should_retry(Some("42601"), 1));
        assert!(!should_retry(None, 1));
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        assert_eq!(retry_delay(1), Duration::from_secs(2));
        assert_eq!(retry_delay(3), Duration::from_secs(6));
        assert_eq!(retry_delay(50), Duration::from_secs(10));
    }

    #[test]
    fn the_migration_statement_timeout_outlasts_the_pool_default() {
        // The pool default is 60 s; a migration must be allowed longer.
        assert_eq!(MIGRATION_STATEMENT_TIMEOUT, "30min");
        assert_eq!(MIGRATION_LOCK_TIMEOUT, "5s");
    }
}
