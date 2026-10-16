//! Every template's source passes the static lint the platform's compile
//! paths run before they build (`talos_compilation::source_lint_errors`):
//! `env!()`, `include_str!()`, `#[path]`, `unsafe` and the other forbidden
//! patterns. The compile check (`make check-catalog`) and the fuel check find
//! the same thing, but only after a build; here an author meets it in the
//! first `cargo test`. The whole source is linted, tests included, as the
//! compile path lints it.

#[test]
fn every_template_passes_the_lint_that_refuses_a_compile() {
    let mut read = 0;
    let mut wrong = Vec::new();
    for dir in talos_catalog_tests::template_dirs() {
        let Ok(source) = std::fs::read_to_string(dir.join("template.rs")) else {
            continue;
        };
        read += 1;
        for e in talos_compilation::source_lint_errors(&source) {
            let at = e.line.map_or(String::new(), |l| format!(" (line {l})"));
            wrong.push(format!(
                "{}{at}: {}",
                dir.file_name().unwrap_or_default().to_string_lossy(),
                e.message
            ));
        }
    }
    assert!(read > 50, "read only {read} templates");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_lint_it_asks_is_the_one_that_refuses_a_compile() {
    // A forbidden pattern is found, and an ordinary source is not.
    assert!(!talos_compilation::source_lint_errors("const K: &str = env!(\"HOME\");").is_empty());
    assert!(talos_compilation::source_lint_errors(
        "pub fn run(input: String) -> Result<String, String> { Ok(input) }"
    )
    .is_empty());
}
