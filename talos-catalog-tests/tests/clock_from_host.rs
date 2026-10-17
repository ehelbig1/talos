//! A template reads the time from the host's clock, never the process's own.
//!
//! The sandbox gives a module the time through `datetime::now_unix()`, which
//! `talos_module_testkit::host::clock::set_unix` drives in a test. A module
//! that calls `chrono::Utc::now()`, `chrono::Local::now()` or
//! `std::time::SystemTime::now()` gets the worker's wall clock instead, and
//! no test can pin it: the authoring lane's `commitments` passed its
//! round-trip test for fourteen days and then failed it when a fixture's due
//! date expired by the real calendar (2026-10-17). Such a module is also
//! replayed against a recording with today's date, so a window it computes
//! ("the next seven days") drifts away from the data it was recorded with.
//!
//! So, over each template's source before its `#[cfg(test)]` module, comments
//! out and string literals skipped: no line calls one of
//! `talos_module_source::clock::OWN_CLOCK_CALLS`. `Instant::now()` is not one
//! of them (a duration, never a date). Templates that were written before
//! this gate and read their own clock are listed in `PREDATING`, which only
//! shrinks.
//!
//! The rule has ONE home, `talos_module_source::clock` (with its own tests);
//! the authoring lane runs the same function over its modules. This file is
//! the catalog's population and its list.

use talos_module_source::clock::own_clock_reads;

/// Templates that read the process's own clock (measured 2026-10-17). Each is
/// a date a test cannot pin: move it to `datetime::now_unix()`, then take it
/// off.
const PREDATING: &[&str] = &[
    "briefing-html-generator",
    "capture-home-assistant",
    "capture-ntfy",
    "google-calendar-list-events",
    "google-health-daily",
    "jwt-validator",
    "plaid-bank-digest",
];

fn templates() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for dir in talos_catalog_tests::template_dirs() {
        let Ok(source) = std::fs::read_to_string(dir.join("template.rs")) else {
            continue;
        };
        out.push((
            dir.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            source,
        ));
    }
    out.sort();
    out
}

#[test]
fn every_template_reads_the_time_from_the_host_clock() {
    let all = templates();
    assert!(all.len() > 50, "found only {} templates", all.len());
    let mut wrong = Vec::new();
    for (slug, source) in &all {
        let reads = own_clock_reads(source);
        if PREDATING.contains(&slug.as_str()) {
            assert!(
                !reads.is_empty(),
                "{slug} reads the host clock now: take it off PREDATING"
            );
            continue;
        }
        wrong.extend(reads.into_iter().map(|r| format!("{slug}: {r}")));
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    for slug in PREDATING {
        assert!(
            all.iter().any(|(s, _)| s == slug),
            "{slug} is on PREDATING and is not a template any more"
        );
    }
}
