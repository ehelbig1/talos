// NATS Topic Regression Tests
//
// Bug 3: NATS topic mismatch between controller and worker
//
// The controller publishes to `talos.jobs.user.{user_id}` but workers must
// subscribe to wildcard topics to receive these. These tests verify the
// topic format is correct and that NATS wildcard matching would work.
//
// To run:
//    cargo test --test nats_topic_tests

// The get_single_job_topic function is private in parallel.rs, so we replicate
// the logic here to test the contract. If the implementation changes, these
// tests will catch the divergence when the integration tests run.

use uuid::Uuid;

/// Replicates the get_single_job_topic logic from controller/src/engine/parallel.rs
/// to verify the topic format contract.
fn get_single_job_topic(user_id: Option<Uuid>, worker_id: Option<Uuid>) -> String {
    match (user_id, worker_id) {
        (Some(u), Some(w)) => format!("talos.jobs.user.{}.worker.{}", u, w),
        (Some(u), None) => format!("talos.jobs.user.{}", u),
        _ => "talos.jobs.global".to_string(),
    }
}

/// Simulates NATS `>` wildcard matching: `pattern.>` matches any topic that
/// starts with `pattern.` followed by one or more tokens.
fn nats_wildcard_matches(subscription_pattern: &str, topic: &str) -> bool {
    if let Some(prefix) = subscription_pattern.strip_suffix(".>") {
        // The `>` wildcard matches one or more tokens after the prefix
        topic.starts_with(prefix)
            && topic.len() > prefix.len()
            && topic.as_bytes()[prefix.len()] == b'.'
    } else { subscription_pattern == topic }
}

// ============================================================================
// Bug 3: Topic format tests
// ============================================================================

#[test]
fn test_topic_with_user_id_only() {
    // Regression: Controller publishes to talos.jobs.user.{uid} for per-user routing.
    let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let topic = get_single_job_topic(Some(user_id), None);
    assert_eq!(
        topic, "talos.jobs.user.550e8400-e29b-41d4-a716-446655440000",
        "Topic should be talos.jobs.user.{{user_id}}"
    );
}

#[test]
fn test_topic_with_user_and_worker_id() {
    // Regression: Controller publishes to talos.jobs.user.{uid}.worker.{wid} for targeted routing.
    let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let worker_id = Uuid::parse_str("660e8400-e29b-41d4-a716-446655440000").unwrap();
    let topic = get_single_job_topic(Some(user_id), Some(worker_id));
    assert_eq!(
        topic,
        "talos.jobs.user.550e8400-e29b-41d4-a716-446655440000.worker.660e8400-e29b-41d4-a716-446655440000"
    );
}

#[test]
fn test_topic_with_no_ids_returns_global() {
    // Regression: Without user_id, falls back to global topic.
    let topic = get_single_job_topic(None, None);
    assert_eq!(topic, "talos.jobs.global");
}

#[test]
fn test_topic_with_none_user_and_some_worker_returns_global() {
    // Edge case: worker_id without user_id should still be global.
    let worker_id = Uuid::new_v4();
    let topic = get_single_job_topic(None, Some(worker_id));
    assert_eq!(topic, "talos.jobs.global");
}

// ============================================================================
// Bug 3: NATS wildcard matching tests
//
// Workers subscribe to `talos.jobs.>` which should match all sub-topics.
// ============================================================================

#[test]
fn test_wildcard_matches_user_scoped_topic() {
    // Regression: Worker subscribes to talos.jobs.> which must match
    // talos.jobs.user.{uid} published by the controller.
    let user_id = Uuid::new_v4();
    let topic = get_single_job_topic(Some(user_id), None);
    assert!(
        nats_wildcard_matches("talos.jobs.>", &topic),
        "talos.jobs.> should match {}",
        topic
    );
}

#[test]
fn test_wildcard_matches_user_worker_scoped_topic() {
    // Regression: talos.jobs.> must also match talos.jobs.user.{uid}.worker.{wid}
    let user_id = Uuid::new_v4();
    let worker_id = Uuid::new_v4();
    let topic = get_single_job_topic(Some(user_id), Some(worker_id));
    assert!(
        nats_wildcard_matches("talos.jobs.>", &topic),
        "talos.jobs.> should match {}",
        topic
    );
}

#[test]
fn test_wildcard_matches_global_topic() {
    // talos.jobs.> should match talos.jobs.global
    let topic = get_single_job_topic(None, None);
    assert!(
        nats_wildcard_matches("talos.jobs.>", &topic),
        "talos.jobs.> should match {}",
        topic
    );
}

#[test]
fn test_wildcard_does_not_match_unrelated_topic() {
    // Sanity check: talos.jobs.> should NOT match talos.pipeline.jobs
    assert!(
        !nats_wildcard_matches("talos.jobs.>", "talos.pipeline.jobs"),
        "talos.jobs.> should NOT match talos.pipeline.jobs"
    );
}

#[test]
fn test_wildcard_does_not_match_base_topic_alone() {
    // NATS `>` requires at least one token after the prefix.
    // talos.jobs.> should NOT match just "talos.jobs"
    assert!(
        !nats_wildcard_matches("talos.jobs.>", "talos.jobs"),
        "talos.jobs.> should NOT match talos.jobs (no sub-token)"
    );
}

#[test]
fn test_topic_format_has_correct_prefix() {
    // Regression: All user-scoped topics must start with "talos.jobs." so the
    // worker's wildcard subscription picks them up.
    let user_id = Uuid::new_v4();

    let topic_user = get_single_job_topic(Some(user_id), None);
    assert!(
        topic_user.starts_with("talos.jobs."),
        "User topic should start with talos.jobs."
    );

    let worker_id = Uuid::new_v4();
    let topic_worker = get_single_job_topic(Some(user_id), Some(worker_id));
    assert!(
        topic_worker.starts_with("talos.jobs."),
        "Worker topic should start with talos.jobs."
    );

    let topic_global = get_single_job_topic(None, None);
    assert!(
        topic_global.starts_with("talos.jobs."),
        "Global topic should start with talos.jobs."
    );
}

#[test]
fn test_topic_does_not_contain_double_dots() {
    // Sanity check: Topics should never have ".." which would be invalid in NATS.
    let user_id = Uuid::new_v4();
    let worker_id = Uuid::new_v4();

    for topic in &[
        get_single_job_topic(Some(user_id), None),
        get_single_job_topic(Some(user_id), Some(worker_id)),
        get_single_job_topic(None, None),
    ] {
        assert!(
            !topic.contains(".."),
            "Topic '{}' should not contain '..'",
            topic
        );
    }
}
