//! A template's `config_schema` names the config keys its source reads, and
//! describes each.
//!
//! The schema is what an installer reads to configure a node, and it is
//! written by hand apart from the code, so it drifts: a key renamed in the
//! source and not in the schema is a node configured with a key nothing reads
//! (`create-calendar-event` declares `TITLE`; its source reads `SUMMARY`).
//!
//! Over the source before its `#[cfg(test)]` module, comments removed:
//!
//! 1. every key the source reads is a property of `config_schema`, with a
//!    non-empty `description`. A key is read by a field
//!    `#[serde(rename = "KEY")]` of a struct whose name contains `Config`, or
//!    by `config.get("KEY")` / `cfg["KEY"]` (a value named `config…`, `cfg…`
//!    or `conf…`);
//! 2. where the module has such a typed config struct (the shape
//!    `make new-template` writes), every declared property is read: a
//!    property nothing reads is a setting that does nothing.
//!
//! Templates written before this gate that do not meet it are listed in
//! `PREDATING`, which only shrinks.
//!
//! The rules have ONE home, `talos_module_source::config_keys` (with their own
//! tests); the authoring lane reads the same scanner. This file is the
//! catalog's population and its list.

use talos_module_source::config_keys::schema_mismatch;

/// Measured 2026-10-16. Each is a schema that says something the module does not do.
const PREDATING: &[&str] = &[
    "create-calendar-event",
    "gcp-run-job-execute",
    "google-calendar-webhook",
    "google-mail-webhook",
    "send-gmail",
    "slack-webhook-listener",
];

#[test]
fn every_template_declares_the_config_keys_its_source_reads() {
    let mut wrong = Vec::new();
    let mut read = 0;
    for dir in talos_catalog_tests::template_dirs() {
        let slug = dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let (Ok(manifest), Ok(source)) = (
            std::fs::read_to_string(dir.join("talos.json")),
            std::fs::read_to_string(dir.join("template.rs")),
        ) else {
            continue;
        };
        read += 1;
        let m: serde_json::Value =
            serde_json::from_str(&manifest).unwrap_or_else(|e| panic!("{slug}: {e}"));
        let problems = schema_mismatch(&m["config_schema"], &source);
        if PREDATING.contains(&slug.as_str()) {
            assert!(
                !problems.is_empty(),
                "{slug} meets the gate now: take it off PREDATING"
            );
            continue;
        }
        wrong.extend(problems.into_iter().map(|p| format!("{slug}: {p}")));
    }
    assert!(read > 50, "read only {read} templates");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
