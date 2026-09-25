//! Call-site pin: the worker's NATS job path runs a module ONCE.
//!
//! `execute_job` hands `execute_job_with_full_features` a `RetryPolicy`, and
//! the runtime re-runs the WHOLE module on transient-looking error text for as
//! many attempts as that policy grants — text the guest can print, judged with
//! no view of `allowed_methods`, capability world or idempotency key. Until
//! 2026-09-25 this call passed a blind three-retry default while the
//! controller that dispatched the job was already retrying method-aware, so a
//! POST node the controller allowed zero retries ran up to four times.
//!
//! `RetryPolicy::controller_dispatched()` is the one home for the answer and is
//! unit-tested in `talos-worker-runtime`. What a test of the constructor cannot
//! see is whether THIS call site uses it — which is what regressed — so this
//! reads `main.rs` itself. It lives in its own file because a pin inside the
//! file it scans matches its own needles (#944/#947).

/// `main.rs` with every column-0 `#[cfg(test)] mod … { … }` region and every
/// whole-line comment removed, so neither test code nor prose can vouch for, or
/// against, the production call.
fn production_source() -> String {
    let src = include_str!("main.rs");
    let mut out = String::new();
    let mut lines = src.lines().peekable();
    while let Some(line) = lines.next() {
        if line == "#[cfg(test)]"
            && lines
                .peek()
                .is_some_and(|next| next.starts_with("mod ") && next.ends_with('{'))
        {
            // Skip to the region's first column-0 closing brace. Conservative
            // in the safe direction: an early stop leaves test code IN.
            for inner in lines.by_ref() {
                if inner == "}" {
                    break;
                }
            }
            continue;
        }
        if line.trim_start().starts_with("//") {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[test]
fn the_nats_job_path_passes_the_controller_dispatched_policy() {
    let prod = production_source();
    let calls = prod.matches("execute_job_with_full_features(").count();
    assert!(
        calls >= 1,
        "vacuity guard: the scan found no execute_job_with_full_features call in main.rs"
    );
    let constructors: Vec<&str> = prod
        .match_indices("RetryPolicy::")
        .map(|(i, _)| {
            let rest = &prod[i..];
            let end = rest.find('(').unwrap_or(rest.len());
            &rest[..end]
        })
        .collect();
    assert_eq!(
        constructors,
        vec!["RetryPolicy::controller_dispatched"],
        "the worker's only RetryPolicy must be controller_dispatched(): a job the \
         controller dispatched is retried by the controller, method-aware, and an \
         in-process retry re-runs the whole module on guest-influenced text"
    );
    assert_eq!(
        calls, 1,
        "one execute_job_with_full_features call, one policy — a second call site \
         must state its own policy and be added here deliberately"
    );
}
