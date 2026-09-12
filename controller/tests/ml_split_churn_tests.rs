//! `DatasetService::assign_splits` writes ONLY the rows whose `split` changes.
//!
//! The holdout is deterministic (`stratified_holdout` sorts by UUID), so on an
//! unchanged dataset every eval re-derives the split the rows already carry.
//! Until 2026-09-12 the method rewrote every row anyway — measured on a live
//! copy: 110 ms, 2 145 heap tuples, 2 373 dirtied pages and a fresh entry in
//! every index (ivfflat included) per eval, for a net change of zero rows.
//! These tests pin the new contract through the REAL service against a real
//! database: the counts the method returns are the rows that moved, a repeat
//! call moves nothing, a changed holdout moves exactly the symmetric
//! difference, and the resulting split is byte-identical to the old shape's.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;
use talos_ml::{AppendExample, DatasetService, ExampleSource, SplitAssignment};
use uuid::Uuid;

fn set_master_key() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
}

/// A closed port: `prepare_examples` must fail fast to a NULL embedding — this
/// test needs rows, not vectors — and never sit in a timeout.
fn declare_dead_embedding_provider() {
    std::env::set_var("EMBEDDING_API_URL", "http://127.0.0.1:1/v1/embeddings");
    std::env::set_var("EMBEDDING_MODEL", "talos-test-none");
    std::env::set_var("EMBEDDING_DIMENSIONS", "1024");
}

async fn seed_user(pool: &sqlx::PgPool, id: Uuid) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'x', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("{id}@ml-split.test"))
    .execute(pool)
    .await
    .expect("seed user");
}

async fn seed_dataset(pool: &sqlx::PgPool, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_datasets (id, user_id, name, task_type) \
         VALUES ($1, $2, $3, 'classification')",
    )
    .bind(id)
    .bind(user_id)
    .bind(format!("ds-{id}"))
    .execute(pool)
    .await
    .expect("seed dataset");
    id
}

async fn dataset_service(pool: &sqlx::PgPool) -> DatasetService {
    set_master_key();
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm.clone()),
    ));
    DatasetService::new(sm)
}

/// Every example id in the dataset, sorted — the same order
/// `stratified_holdout` uses, so a prefix is a realistic holdout.
async fn ids(pool: &sqlx::PgPool, ds: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar("SELECT id FROM ml_examples WHERE dataset_id = $1 ORDER BY id")
        .bind(ds)
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn split_of(pool: &sqlx::PgPool, ds: Uuid) -> Vec<(Uuid, Option<String>)> {
    sqlx::query_as("SELECT id, split FROM ml_examples WHERE dataset_id = $1 ORDER BY id")
        .bind(ds)
        .fetch_all(pool)
        .await
        .unwrap()
}

/// The OLD shape, verbatim, applied to a copy of the rows — the oracle the
/// new shape must agree with.
fn old_shape(all: &[Uuid], holdout: &[Uuid]) -> Vec<(Uuid, Option<String>)> {
    let h: BTreeSet<Uuid> = holdout.iter().copied().collect();
    all.iter()
        .map(|id| {
            (
                *id,
                Some(if h.contains(id) { "holdout" } else { "train" }.to_string()),
            )
        })
        .collect()
}

async fn seed_examples(dsvc: &DatasetService, pool: &sqlx::PgPool, ds: Uuid, n: usize) {
    let tenancy = {
        let mut conn = pool.acquire().await.unwrap();
        dsvc.dataset_tenancy(&mut conn, ds).await.unwrap()
    };
    for i in 0..n {
        let ex = AppendExample {
            features_text: format!("row-{i}"),
            label: if i % 2 == 0 { "a" } else { "b" }.to_string(),
            source: ExampleSource::LlmBootstrap,
            example_key: Some(format!("row-{i}")),
        };
        let prepared = dsvc.prepare_examples(ds, tenancy, vec![ex]).await.unwrap();
        let mut conn = pool.acquire().await.unwrap();
        dsvc.insert_prepared(&mut conn, ds, tenancy, prepared)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn a_repeat_assignment_moves_nothing_and_a_changed_one_moves_the_difference() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    declare_dead_embedding_provider();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user).await;
    let dsvc = dataset_service(&pool).await;
    seed_examples(&dsvc, &pool, ds, 12).await;
    let all = ids(&pool, ds).await;
    assert_eq!(all.len(), 12);
    // Freshly appended rows carry no split yet — NULL is DISTINCT from both
    // values, so the first assignment must write every row (as before).
    assert!(
        split_of(&pool, ds).await.iter().all(|(_, s)| s.is_none()),
        "precondition: appended rows start with split NULL"
    );

    let holdout_a: Vec<Uuid> = all[..3].to_vec();
    let mut conn = pool.acquire().await.unwrap();
    let first = dsvc.assign_splits(&mut conn, ds, &holdout_a).await.unwrap();
    assert_eq!(
        first,
        SplitAssignment {
            moved_to_train: 9,
            moved_to_holdout: 3
        },
        "first assignment writes every row"
    );
    assert_eq!(split_of(&pool, ds).await, old_shape(&all, &holdout_a));

    // The steady state: the same deterministic holdout again. The old shape
    // rewrote all 12 rows here; the new one must touch none.
    let repeat = dsvc.assign_splits(&mut conn, ds, &holdout_a).await.unwrap();
    assert_eq!(
        repeat,
        SplitAssignment::default(),
        "a repeat assignment moves nothing"
    );
    assert_eq!(split_of(&pool, ds).await, old_shape(&all, &holdout_a));

    // A changed holdout: rows 3..5 enter, row 0 leaves — exactly the
    // symmetric difference moves, and the result still equals the old shape's.
    let holdout_b: Vec<Uuid> = all[1..5].to_vec();
    let changed = dsvc.assign_splits(&mut conn, ds, &holdout_b).await.unwrap();
    assert_eq!(
        changed,
        SplitAssignment {
            moved_to_train: 1,
            moved_to_holdout: 2
        },
        "only the rows whose split changed are written"
    );
    assert_eq!(split_of(&pool, ds).await, old_shape(&all, &holdout_b));
    // CONTROL: the readers the eval uses see the new split.
    let holdout_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ml_examples WHERE dataset_id = $1 AND split = 'holdout'",
    )
    .bind(ds)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(holdout_rows, 4);
}

/// The proof that "moves nothing" is about ROW VERSIONS, not just the
/// returned counts: `xmin` is the inserting transaction of the current tuple
/// version, so an UPDATE — even to the same value — mints a new one. After a
/// repeat assignment every row's `xmin` must be unchanged.
#[tokio::test]
async fn a_repeat_assignment_leaves_every_row_version_in_place() {
    let (pool, _db) = common::isolated_db_pool().await;
    set_master_key();
    declare_dead_embedding_provider();
    let user = Uuid::new_v4();
    seed_user(&pool, user).await;
    let ds = seed_dataset(&pool, user).await;
    let dsvc = dataset_service(&pool).await;
    seed_examples(&dsvc, &pool, ds, 8).await;
    let all = ids(&pool, ds).await;
    let holdout: Vec<Uuid> = all[..2].to_vec();
    let mut conn = pool.acquire().await.unwrap();
    dsvc.assign_splits(&mut conn, ds, &holdout).await.unwrap();
    let xmins = |pool: &sqlx::PgPool| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Vec<String>>(
                "SELECT array_agg(xmin::text ORDER BY id) FROM ml_examples WHERE dataset_id = $1",
            )
            .bind(ds)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let before = xmins(&pool).await;
    let repeat = dsvc.assign_splits(&mut conn, ds, &holdout).await.unwrap();
    assert_eq!(repeat, SplitAssignment::default());
    assert_eq!(
        xmins(&pool).await,
        before,
        "no row version was minted by the repeat"
    );
    // CONTROL: a real change DOES mint new versions for exactly the moved rows.
    let moved = dsvc.assign_splits(&mut conn, ds, &all[..3]).await.unwrap();
    assert_eq!(
        moved,
        SplitAssignment {
            moved_to_train: 0,
            moved_to_holdout: 1
        }
    );
    let after = xmins(&pool).await;
    let differing = before
        .iter()
        .zip(after.iter())
        .filter(|(b, a)| b != a)
        .count();
    assert_eq!(differing, 1, "exactly the one moved row got a new version");
}
