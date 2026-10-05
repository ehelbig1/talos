//! The `ops_alerts_digest` node's `sources` filter, end to end against
//! Postgres: the repository query the node uses, and the Postgres reader the
//! engine calls.
//!
//! Why it exists: a reader that forwards the platform's own failure alerts to
//! a phone must see them even when hundreds of work-email alerts outrank them
//! (the digest returns at most 25, severity-ranked). And a filter must never
//! widen: an empty list matches no alert.

mod common;

use talos_ops_alerts_repository::{NewOpsAlert, OpsAlertRepository};
use talos_workflow_engine_core::OpsAlertsReader;
use uuid::Uuid;

async fn seed_user(pool: &sqlx::Pool<sqlx::Postgres>) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("digest-sources-{user}@talos.test"))
    .execute(pool)
    .await
    .expect("seed user");
    user
}

fn alert(source: &str, n: usize, severity: &str) -> NewOpsAlert {
    NewOpsAlert {
        source: source.to_string(),
        external_id: None,
        dedup_key: format!("{source}|made-up-{n}"),
        title: format!("made-up {source} alert {n}"),
        resource: None,
        severity_raw: None,
        severity_hint: Some(severity.to_string()),
        raw: None,
    }
}

#[tokio::test]
async fn sources_narrow_top_active_and_an_empty_list_matches_nothing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = OpsAlertRepository::new(pool.clone());

    // Thirty high-severity alerts from a noisy source outrank the one
    // medium alert from the source a reader wants.
    for n in 0..30 {
        repo.ingest(user, None, alert("made-up-email", n, "high"))
            .await
            .expect("ingest noise");
    }
    repo.ingest(user, None, alert("watched", 0, "medium"))
        .await
        .expect("ingest watched");

    let unfiltered = repo.list_active_ranked(user, 25).await.unwrap();
    assert_eq!(unfiltered.len(), 25);
    assert!(
        unfiltered.iter().all(|a| a.source == "made-up-email"),
        "without a filter the watched alert is ranked out of the top 25"
    );

    let watched = vec!["watched".to_string()];
    let filtered = repo
        .list_active_ranked_from(user, 25, Some(&watched))
        .await
        .unwrap();
    assert_eq!(
        filtered
            .iter()
            .map(|a| a.source.as_str())
            .collect::<Vec<_>>(),
        vec!["watched"]
    );

    let none = repo
        .list_active_ranked_from(user, 25, Some(&[]))
        .await
        .unwrap();
    assert!(
        none.is_empty(),
        "an empty filter must match nothing, got {}",
        none.len()
    );

    // Another user's alert from the same source is never returned.
    let other = seed_user(&pool).await;
    repo.ingest(other, None, alert("watched", 1, "critical"))
        .await
        .expect("ingest other user");
    let mine = repo
        .list_active_ranked_from(user, 25, Some(&watched))
        .await
        .unwrap();
    assert_eq!(mine.len(), 1);
}

#[tokio::test]
async fn the_reader_passes_the_filter_and_reports_when_an_alert_reopened() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let repo = OpsAlertRepository::new(pool.clone());
    for n in 0..3 {
        repo.ingest(user, None, alert("made-up-email", n, "high"))
            .await
            .unwrap();
    }
    repo.ingest(user, None, alert("watched", 0, "medium"))
        .await
        .unwrap();

    let reader = talos_engine::ops_alerts_reader::PostgresOpsAlertsReader::new(pool.clone());
    let watched = vec!["watched".to_string()];
    let snap = reader
        .snapshot(user, 10, Some(&watched))
        .await
        .expect("snapshot");
    let top = snap["top_active"].as_array().expect("top_active");
    assert_eq!(top.len(), 1);
    assert_eq!(top[0]["source"], "watched");
    assert!(top[0]["reopened_at"].is_null());
    // The digest counts stay over every active alert.
    let counted: i64 = snap["digest"]["active_by_source"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["count"].as_i64().unwrap())
        .sum();
    assert_eq!(counted, 4);

    // Resolve, then raise again: the row reopens and says when.
    repo.resolve_by_dedup_key(user, "watched|made-up-0")
        .await
        .expect("resolve");
    repo.ingest(user, None, alert("watched", 0, "medium"))
        .await
        .unwrap();
    let snap = reader.snapshot(user, 10, Some(&watched)).await.unwrap();
    assert!(
        snap["top_active"][0]["reopened_at"].is_string(),
        "{}",
        snap["top_active"][0]
    );
}
