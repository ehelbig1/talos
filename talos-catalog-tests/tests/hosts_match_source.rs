//! A template's granted hosts are the hosts its source addresses, no more and
//! no fewer.
//!
//! `allowed_hosts` is written by hand in `talos.json`, apart from the code
//! that makes the requests, so the two drift. Both directions cost:
//!
//! * **called, not granted** — the worker refuses the request
//!   (`forbiddenhost`) and the part the module wanted is "unread" on every
//!   run. `gcp-binauthz-evidence` shipped in the authoring lane granting two of
//!   the four hosts its source calls (found 2026-10-16).
//! * **granted, not called** — a grant nothing uses is reach the module has
//!   for no reason: the least-privilege rule, broken quietly.
//!
//! So, over each template's source before its `#[cfg(test)]` module, string
//! literals only (comments are not code):
//!
//! 1. in a network world, every host a literal addresses as `http(s)://host`
//!    is in `allowed_hosts`, unless the literal's line says
//!    `// host-not-requested: <why>` (a URL kept as data — a link for a person,
//!    a JSON-LD context — and never fetched);
//! 2. every granted host other than `*` is named in some string literal, with
//!    or without a scheme (`"sandbox.plaid.com"` counts: the URL is built from
//!    it).
//!
//! A `*` grant is narrowed by the installer and is not judged here. Templates
//! that were written before this gate and do not meet it are listed in
//! `PREDATING`, which only shrinks.
//!
//! The rules themselves have ONE home, `talos_module_source::hosts` (with their
//! own tests, mutation-proven there); the authoring lane runs the same
//! function over its modules. This file is the catalog's population and its
//! list.

use talos_module_source::hosts::mismatch;

/// Templates that grant hosts their source never names (measured 2026-10-16).
/// Each is a least-privilege gap to close: narrow its grant, then take it off.
const PREDATING: &[&str] = &[
    "create-calendar-event",
    "google-calendar-webhook",
    "google-mail-webhook",
    "send-gmail",
    "send-slack-message",
    "slack-webhook-listener",
];

fn templates() -> Vec<(String, String, Vec<String>, String)> {
    let mut out = Vec::new();
    for dir in talos_catalog_tests::template_dirs() {
        let (Ok(manifest), Ok(source)) = (
            std::fs::read_to_string(dir.join("talos.json")),
            std::fs::read_to_string(dir.join("template.rs")),
        ) else {
            continue;
        };
        let m: serde_json::Value =
            serde_json::from_str(&manifest).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        let world = m["capability_world"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let granted = m["allowed_hosts"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|h| h.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        out.push((
            dir.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            world,
            granted,
            source,
        ));
    }
    out.sort();
    out
}

#[test]
fn every_template_grants_the_hosts_its_source_addresses_and_no_others() {
    let all = templates();
    assert!(all.len() > 50, "found only {} templates", all.len());
    let mut wrong = Vec::new();
    for (slug, world, granted, source) in &all {
        let problems = mismatch(world, granted, source);
        if PREDATING.contains(&slug.as_str()) {
            assert!(
                !problems.is_empty(),
                "{slug} meets the gate now: take it off PREDATING"
            );
            continue;
        }
        wrong.extend(problems.into_iter().map(|p| format!("{slug}: {p}")));
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    for slug in PREDATING {
        assert!(
            all.iter().any(|(s, ..)| s == slug),
            "{slug} is on PREDATING and is not a template any more"
        );
    }
}
