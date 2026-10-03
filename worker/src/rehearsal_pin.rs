//! Call-site pin: a dispatched job never runs against recorded HTTP answers.
//!
//! `SecurityPolicy::http_replay` makes `http::fetch` answer from recordings
//! instead of sending. It exists for the controller's `test_module` rehearsal.
//! A real job that received canned responses would report success over data
//! that was never fetched, so the worker must leave it unset on every policy it
//! builds. Both policies in `main.rs` are full struct literals, so the field has
//! to be written out; this checks what it is written as.

#[test]
fn every_policy_the_worker_builds_leaves_recorded_answers_off() {
    let prod = crate::retry_policy_pin::production_source();
    let field = "http_replay:";
    let set = prod.matches(field).count();
    assert!(
        set >= 2,
        "vacuity guard: expected the single-job and the pipeline-step policy, found {set}"
    );
    assert_eq!(
        set,
        prod.matches("http_replay: None,").count(),
        "the worker sets recorded HTTP answers on a dispatched job"
    );
    assert_eq!(
        prod.matches("http_replay").count(),
        set,
        "main.rs reads or assigns recorded HTTP answers somewhere other than a policy literal"
    );
}
