//! A template's secret grant is `requires_secrets`. The catalog's manifest
//! parser (`talos_registry::reconcile::CatalogManifest`) reads that key and no
//! other, so a grant written under `allowed_secrets` (the name it has on a
//! platform's module row) is dropped without a word, and the installed copy
//! can read none of the secrets it was written for. `promote-module.py` wrote
//! that key until 2026-10-16.

use std::path::PathBuf;

#[test]
fn no_template_writes_its_secret_grant_under_a_key_the_catalog_does_not_read() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../module-templates");
    let mut read = 0;
    let mut wrong = Vec::new();
    for entry in std::fs::read_dir(&root).expect("module-templates") {
        let manifest = entry.expect("entry").path().join("talos.json");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        let value: serde_json::Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", manifest.display()));
        read += 1;
        if value.get("allowed_secrets").is_some() {
            wrong.push(manifest.display().to_string());
        }
    }
    assert!(read > 50, "read only {read} manifests");
    assert!(wrong.is_empty(), "these manifests grant secrets under `allowed_secrets`, which the catalog ignores; name the key `requires_secrets`:\n{}", wrong.join("\n"));
}
