//! Every adapter that takes a base address from its configuration checks it
//! with the ONE rule whose home is `talos_integration_helpers::base_address`
//! (security review 2026-10-14 F-11; one validator 2026-10-15). An adapter is
//! compiled on its own and cannot link that crate, so it carries the rule's
//! block byte for byte; this test holds every copy equal to the home, where
//! the rule's own tests run. Each adapter's `a_base_with_userinfo_is_refused`
//! drives its copy through the adapter's own entry point.

const BEGIN: &str = "// ── base address contract ──";
const END: &str = "// ── end base address contract ──";

/// The adapters that read a base address, and the one place a new one must
/// be added.
const ADAPTERS: &[&str] = &[
    "notify-ntfy",
    "notify-home-assistant",
    "control-home-assistant",
    "capture-ntfy",
    "capture-home-assistant",
];

fn block(path: &std::path::Path) -> String {
    let source =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let start = source
        .find(BEGIN)
        .unwrap_or_else(|| panic!("{}: no base address block", path.display()));
    let end = source[start..]
        .find(END)
        .unwrap_or_else(|| panic!("{}: the base address block is not closed", path.display()));
    assert_eq!(
        source.matches(BEGIN).count(),
        1,
        "{}: one block per file",
        path.display()
    );
    source[start..start + end].to_string()
}

fn root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

#[test]
fn every_adapter_carries_the_homes_base_address_block() {
    let home = block(&root().join("talos-integration-helpers/src/base_address.rs"));
    assert!(home.contains("fn https_base("), "the home names the rule");
    for slug in ADAPTERS {
        let copy = block(
            &root()
                .join("module-templates")
                .join(slug)
                .join("template.rs"),
        );
        assert!(
            copy == home,
            "{slug}'s base address block differs from talos-integration-helpers/src/base_address.rs; \
             they must be byte-identical"
        );
    }
}

/// Templates that name such a setting but send nothing to it, each with why.
const NOT_A_REQUEST_BASE: &[(&str, &str)] = &[(
    "briefing-html-generator",
    "writes the address into HTML links; a minimal-node with no hosts, it makes no request",
)];

/// A template that reads a base-address setting is on the list above: one
/// whose source names `BASE_URL` or `SERVER_URL` and is not listed fails here.
#[test]
fn every_template_that_reads_a_base_address_is_listed() {
    let dir = root().join("module-templates");
    let mut unlisted = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("module-templates") {
        let entry = entry.expect("entry");
        let slug = entry.file_name().to_string_lossy().into_owned();
        let Ok(source) = std::fs::read_to_string(entry.path().join("template.rs")) else {
            continue;
        };
        let reads_base = source.contains("\"BASE_URL\"") || source.contains("\"SERVER_URL\"");
        let exempt = NOT_A_REQUEST_BASE.iter().any(|(s, _)| *s == slug);
        if reads_base && !ADAPTERS.contains(&slug.as_str()) && !exempt {
            unlisted.push(slug);
        }
    }
    assert!(
        unlisted.is_empty(),
        "templates read a base address without the shared rule: {unlisted:?}"
    );
}
