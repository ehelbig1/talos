//! `ChannelStore::get_entry` must answer THREE ways, not two.
//!
//! Gated on `TALOS_TEST_DATABASE_URL` (a migrated database) and run by
//! `scripts/test-integration.sh`. Only a live database can evaluate the
//! property: "the row is absent" is produced by
//! `talos_integration_state::execute_op`'s `row_opt.ok_or(KeyNotFound)`
//! against a real SELECT, and "we could not look" is produced by a real
//! pool failure. Neither is reachable from a unit test.
//!
//! ## What this pins, and why it is written this way
//!
//! Before the split, `execute_op`'s `Err(KeyNotFound)` was mapped through
//! `.map_err(|e| anyhow!("integration_state get failed: {:?}", e))?`, so a
//! MISSING KEY came back as `Err`. `Ok(None)` was unreachable, and every
//! caller therefore had to treat "no such row" and "the database did not
//! answer" as one outcome — which is how three probe handlers answered a
//! pool timeout with `404 "Watch not found"` and how three `stop_watch`
//! paths answered one with `Ok(())`, i.e. reported a stop that never
//! happened.
//!
//! `absent_key_is_not_a_failure` is written in the PRE-SPLIT vocabulary on
//! purpose: `get_entry` already returned `Result<Option<StoredEntry>>`
//! before this change, so this file compiles unchanged against the tree
//! that has the defect and fails there by ASSERTION (it observes
//! `Err(integration_state get failed: KeyNotFound)` where it requires
//! `Ok(None)`), not by a type error. A compile failure would prove
//! nothing.
//!
//! `unreadable_store_is_not_an_absence` is the control in the other
//! direction: it must stay `Err` on both trees. Without it, "map
//! everything to `Ok(None)`" would pass the first test — turning a
//! failure-reported-as-absent bug into a worse one.

use serde_json::json;
use talos_integration_helpers::state_store::ChannelStore;
use talos_memory::integration_state_rpc::IndexedSlots;
use uuid::Uuid;

const INTEGRATION: &str = "absence_vs_failure_test";
const PREFIX: &str = "watch/";

async fn pool() -> Option<sqlx::PgPool> {
    let url = std::env::var("TALOS_TEST_DATABASE_URL").ok()?;
    if url.trim().is_empty() {
        return None;
    }
    Some(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect to TALOS_TEST_DATABASE_URL"),
    )
}

#[tokio::test]
async fn absent_key_is_not_a_failure() {
    let Some(pool) = pool().await else {
        eprintln!("skipping: TALOS_TEST_DATABASE_URL unset");
        return;
    };
    let store = ChannelStore::new(pool.clone(), INTEGRATION, PREFIX);
    let user = Uuid::new_v4();
    let never_written = Uuid::new_v4();

    let got = store.get_entry(user, never_written).await;
    match got {
        Ok(None) => {}
        Ok(Some(_)) => panic!("a uuid that was never written must not resolve to a row"),
        Err(e) => panic!(
            "an absent key must be Ok(None), not an error — a caller cannot \
             tell this apart from a pool timeout: {e:?}"
        ),
    }
    pool.close().await;
}

#[tokio::test]
async fn present_key_still_reads_back() {
    // Control: the split must not have broken the ordinary path.
    let Some(pool) = pool().await else {
        eprintln!("skipping: TALOS_TEST_DATABASE_URL unset");
        return;
    };
    let store = ChannelStore::new(pool.clone(), INTEGRATION, PREFIX);
    let user = Uuid::new_v4();
    let id = Uuid::new_v4();

    store
        .set(
            user,
            id,
            json!({"marker": "present"}),
            Some(3600),
            IndexedSlots::default(),
        )
        .await
        .expect("set");

    let entry = store
        .get_entry(user, id)
        .await
        .expect("read must succeed")
        .expect("a row that was just written must be Some");
    assert!(entry.value.contains("present"), "value: {}", entry.value);

    store.delete(user, id).await.expect("delete");
    // And once deleted it is ABSENT, not an error.
    assert!(
        matches!(store.get_entry(user, id).await, Ok(None)),
        "a deleted row must read as Ok(None)"
    );
    pool.close().await;
}

#[tokio::test]
async fn unreadable_store_is_not_an_absence() {
    // The other direction, and the reason the first test is not enough:
    // if `get_entry` folded EVERY error into `Ok(None)`, the absent-key
    // test above would pass while every caller silently concluded "no
    // such row" from a database outage.
    let Some(pool) = pool().await else {
        eprintln!("skipping: TALOS_TEST_DATABASE_URL unset");
        return;
    };
    // Closing the pool is the cheapest faithful stand-in for "the
    // database did not answer": every subsequent acquire fails.
    pool.close().await;
    let store = ChannelStore::new(pool, INTEGRATION, PREFIX);

    let got = store.get_entry(Uuid::new_v4(), Uuid::new_v4()).await;
    assert!(
        got.is_err(),
        "an unreadable store must surface as Err, never as Ok(None) — \
         'we could not look' is not 'it is not there': {got:?}"
    );
}
