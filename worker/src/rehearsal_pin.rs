//! Call-site pin: a dispatched job never runs with a rehearsal option.
//!
//! Three `SecurityPolicy` fields exist for the controller's `test_module` and
//! nothing else: `http_replay` answers `http::fetch` from recordings instead
//! of sending, `http_capture` keeps the responses a run receives, and
//! `fuel_profile` installs a call hook on the store. A real job that received
//! canned responses would report success over data that was never fetched;
//! one that captured would hold response bodies nobody asked it to keep; one
//! that profiled would pay for a hook on every host call. The worker must
//! leave all three unset on every policy it builds. Both policies in `main.rs`
//! are full struct literals, so each field has to be written out; this checks
//! what it is written as.

#[test]
fn every_policy_the_worker_builds_leaves_the_rehearsal_options_off() {
    let prod = crate::retry_policy_pin::production_source();
    for field in ["http_replay", "http_capture", "fuel_profile"] {
        let set = prod.matches(&format!("{field}:")).count();
        assert!(
            set >= 2,
            "vacuity guard: expected {field} on the single-job and the pipeline-step policy, found {set}"
        );
        assert_eq!(
            set,
            prod.matches(&format!("{field}: None,")).count(),
            "the worker sets {field} on a dispatched job"
        );
        assert_eq!(
            prod.matches(field).count(),
            set,
            "main.rs reads or assigns {field} somewhere other than a policy literal"
        );
    }
}
