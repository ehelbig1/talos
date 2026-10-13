//! Tearing a test database down does not wait out a login that the teardown
//! itself froze (2026-10-13).
//!
//! `TestDb::drop` runs `DROP DATABASE … WITH (FORCE)` on another thread. Until
//! this date it JOINED that thread, which blocks the test's current-thread
//! runtime; a connection some task of that runtime was still opening then
//! stops in the middle of its login, the drop cannot finish until every
//! backend has answered it, and a backend waiting on its client's login
//! answers only when `authentication_timeout` ends it — 60 s on a stock
//! server, 5 s on the disposable ones this repository starts. Every test that
//! drove `create_workflow` paid it: the handler returns in 50 ms and leaves two
//! background tasks on the pool.
//!
//! The login is stopped by hand here, so the test does not depend on a race.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, PgConnection};
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Longer than the harness waits for its drop, shorter than the shortest
/// `authentication_timeout` any Postgres these tests run against has (5 s).
const TEARDOWN_LIMIT: Duration = Duration::from_secs(3);
const _: () = assert!(common::TEST_DB_DROP_WAIT.as_millis() < TEARDOWN_LIMIT.as_millis());

/// One at a time. A login stopped in the middle holds up EVERY `DROP DATABASE`
/// on the server, not only the one for its own database, so the first test
/// below would make the second one's drop slow.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Start a login to `database` and stop in the middle of it: send the startup
/// packet, read the server's request for a password, and never answer.
async fn open_a_login_and_stop(opts: &PgConnectOptions, database: &str) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect((opts.get_host(), opts.get_port()))
        .await
        .expect("reach the test Postgres");

    let mut body = Vec::new();
    body.extend_from_slice(&196_608_i32.to_be_bytes()); // protocol 3.0
    for part in ["user", opts.get_username(), "database", database] {
        body.extend_from_slice(part.as_bytes());
        body.push(0);
    }
    body.push(0);
    let length = i32::try_from(body.len() + 4).expect("a short packet");
    let mut packet = length.to_be_bytes().to_vec();
    packet.extend_from_slice(&body);
    stream.write_all(&packet).await.expect("send the startup");

    // 'R', a length, and which authentication the server asks for.
    let mut reply = [0u8; 9];
    stream
        .read_exact(&mut reply)
        .await
        .expect("read the server's authentication request");
    assert_eq!(reply[0], b'R', "an authentication request, got {reply:?}");
    let asked = i32::from_be_bytes([reply[5], reply[6], reply[7], reply[8]]);
    assert_ne!(
        asked, 0,
        "this server let the connection in without a password, so there is no \
         login to stop in the middle of and the test would prove nothing"
    );
    stream
}

async fn database_exists(admin: &mut PgConnection, database: &str) -> bool {
    let found: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_database WHERE datname = $1")
        .bind(database)
        .fetch_one(admin)
        .await
        .expect("read pg_database");
    found == 1
}

/// The shape of a `#[tokio::test]` — a current-thread runtime that runs the
/// body and is then dropped — written out, so the test can look at the server
/// after the runtime has gone.
#[test]
fn a_teardown_does_not_wait_out_a_login_that_its_own_wait_froze() {
    let _alone = ONE_AT_A_TIME.blocking_lock();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let (opts, database, teardown) = runtime.block_on(async {
        let (pool, db) = common::isolated_db_pool().await;
        let database: String = sqlx::query_scalar("SELECT current_database()")
            .fetch_one(&pool)
            .await
            .expect("the clone's name");
        let opts = PgConnectOptions::from_str(&std::env::var("DATABASE_URL").expect("set"))
            .expect("a connection string");

        // A task of THIS runtime holds a half-made connection to the clone, as
        // a task a handler spawned holds the pool connection it is opening.
        let stopped = open_a_login_and_stop(&opts, &database).await;
        tokio::spawn(async move {
            let _open = stopped;
            std::future::pending::<()>().await;
        });

        let started = Instant::now();
        drop(db);
        (opts, database, started.elapsed())
    });

    assert!(
        teardown < TEARDOWN_LIMIT,
        "dropping the test database took {teardown:?}: it waited for a login \
         that cannot finish while the drop blocks this runtime"
    );

    // What the end of a `#[tokio::test]` does next: the task goes, and its
    // socket with it.
    drop(runtime);

    // The drop the harness stopped waiting for still happens.
    let removed = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(async {
            let mut admin = PgConnection::connect_with(&opts.database("postgres"))
                .await
                .expect("connect to the maintenance database");
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if !database_exists(&mut admin, &database).await {
                    break true;
                }
                if Instant::now() > deadline {
                    break false;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
    assert!(
        removed,
        "the clone {database} was left behind: the teardown stopped waiting \
         and the drop never finished"
    );
}

/// With nothing in the way, the clone is gone by the time the drop returns —
/// the wait is bounded, not skipped. A drop that had only been started could
/// be cut off by the end of the test process.
#[tokio::test]
async fn an_ordinary_teardown_has_removed_the_database_when_it_returns() {
    let _alone = ONE_AT_A_TIME.lock().await;
    let (pool, db) = common::isolated_db_pool().await;
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .expect("the clone's name");
    let opts = PgConnectOptions::from_str(&std::env::var("DATABASE_URL").expect("set"))
        .expect("a connection string");
    let mut admin = PgConnection::connect_with(&opts.database("postgres"))
        .await
        .expect("connect to the maintenance database");
    assert!(database_exists(&mut admin, &database).await);

    drop(db);

    assert!(
        !database_exists(&mut admin, &database).await,
        "the clone {database} is still there after its teardown returned"
    );
}
