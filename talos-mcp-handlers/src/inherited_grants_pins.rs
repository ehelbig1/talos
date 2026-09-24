//! Pins that every writer of a module row carries the METHOD grant, not only
//! the host grant.
//!
//! This module lives in its own file DELIBERATELY. Its first draft sat inside
//! `sandbox.rs`, one of the three files it scans through `include_str!`, so it
//! could not be measured against that file's pre-fix state — reverting the
//! file to reproduce the defect deleted the test along with it. A pin that
//! cannot be run against the tree it vouches for proves less than it appears
//! to, the same reason check 58's source pins must not match their own needle
//! line.

/// Return the `[start, end)` byte spans of every `WasmModule { … }` struct
/// literal in `src`, by brace balance.
///
/// TEXTUAL, and it says so: a `{` inside a string literal or a comment inside
/// the span ends it early. That direction is a FALSE NEGATIVE (a short span
/// sees fewer fields), which is why the caller also asserts a floor on how
/// many literals it found.
fn wasm_module_literals(src: &str) -> Vec<&str> {
    // Assembled so this file cannot match itself if it is ever scanned.
    let needle = format!("WasmModule {}", "{");
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(&needle) {
        let open = from + rel + needle.len() - 1; // index of the '{'
        let mut depth = 0i32;
        let mut i = open;
        while i < bytes.len() {
            match bytes[i] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        out.push(&src[open..=i]);
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        from = open + 1;
    }
    out
}

/// Every writer that builds a module row from a template must carry the method
/// grant, not only the host grant.
///
/// **This pin is TEXTUAL and says so.** It cannot prove the value is right; it
/// proves that no `WasmModule` literal takes `allowed_hosts` from a template
/// or grants value while hardcoding an empty `allowed_methods` — the exact
/// shape all four pre-fix writers had. Driving those four end to end needs a
/// database, a compilation container and an `McpState`, so this is the guard
/// that fits in a unit test.
///
/// # Measured, not asserted
///
/// Against `origin/main` at `fef2c163` this reports **4 of 4**:
/// `sandbox:compile_template`, `sandbox:restore_pinned_modules`, the replay
/// service, and the GraphQL `createModuleFromTemplate` twin. 0 after.
///
/// Its first draft used a ±3-line window and reported **3 of 4** — it missed
/// the GraphQL twin, whose `allowed_methods` and `allowed_hosts` sit NINE
/// lines apart, i.e. precisely the site check 68 was written about and that
/// this package forgot again. Scanning the whole struct literal is what closed
/// that, and the 75%-recall draft is recorded because a pin that misses the
/// site most likely to be forgotten is the gate-that-doesn't-gate shape.
#[test]
fn no_module_writer_carries_hosts_while_dropping_methods() {
    // Needles are ASSEMBLED so this test cannot match its own source.
    let hosts_from_template = format!("allowed_hosts: {}.allowed_hosts", "template");
    let hosts_from_grants = format!("allowed_hosts: {}.allowed_hosts", "grants");
    let empty_methods = format!("allowed_{}: vec![]", "methods");

    let files = [
        ("sandbox", include_str!("sandbox.rs")),
        (
            "replay-service",
            include_str!("../../talos-replay-service/src/lib.rs"),
        ),
        (
            "graphql-twin",
            include_str!("../../talos-api/src/schema/modules/mutations.rs"),
        ),
    ];

    let mut literals = 0usize;
    let mut carriers = 0usize;
    let mut violations: Vec<String> = Vec::new();

    for (label, src) in files {
        for lit in wasm_module_literals(src) {
            literals += 1;
            let carries_template_hosts =
                lit.contains(&hosts_from_template) || lit.contains(&hosts_from_grants);
            if !carries_template_hosts {
                continue;
            }
            carriers += 1;
            if lit.contains(&empty_methods) {
                violations.push(label.to_string());
            }
        }
    }

    assert!(
        violations.is_empty(),
        "{} module writer(s) carry a template host grant and hardcode an empty \
         allowed_methods in the same literal — since 2026-09-24 that mints a \
         module holding an egress allowlist it can never use: {violations:?}",
        violations.len()
    );
    assert!(
        literals >= 4,
        "expected at least 4 WasmModule literals across the three files, found \
         {literals} — the brace scan stopped matching, so it is vouching for nothing"
    );
    assert!(
        carriers >= 4,
        "expected at least 4 template-derived module writers, found {carriers} — \
         the grant needles stopped matching, so this is vouching for nothing"
    );
}

/// `run_sandbox`'s execution call must pass the RESOLVED method grant.
///
/// A guard at the resolver cannot see the call site (checks 74b/79b), and the
/// call site is exactly where the 2026-09-24 regression lived: the resolver did
/// not exist and the call passed a hardcoded empty list beside a
/// caller-supplied `allowed_hosts`. `resolve_sandbox_methods` needs a database,
/// a compilation container and an `McpState` to drive end to end, so this pin
/// is TEXTUAL and says so — it proves the resolved value REACHES the runtime,
/// not that the runtime honours it.
#[test]
fn run_sandbox_passes_the_resolved_method_grant() {
    let src = include_str!("sandbox.rs");
    // Assembled needles: this file must not vouch for itself.
    let resolver = format!("resolve_sandbox_{}(args)", "methods");
    let exec = format!("execute_job_with_full_{}(", "features");

    assert!(
        src.contains(&resolver),
        "run_sandbox no longer resolves its method grant through the one home"
    );

    // Find the run_sandbox execution call and read its third positional
    // argument — `allowed_hosts` is second, `allowed_methods` third.
    let at = src
        .find(&exec)
        .expect("the sandbox execution call site has moved or been renamed");
    let window: String = src[at..].lines().take(6).collect::<Vec<_>>().join("\n");
    assert!(
        window.contains("egress.allowed_hosts"),
        "the sandbox execution call no longer passes the posture-narrowed hosts; \
         this pin is reading the wrong call site: {window}"
    );
    assert!(
        !window.contains("vec![]"),
        "the sandbox execution call hardcodes an empty grant again — that is the \
         2026-09-24 regression verbatim, and it makes run_sandbox unable to issue \
         any HTTP request: {window}"
    );
    assert!(
        window.contains("allowed_methods"),
        "the sandbox execution call no longer names allowed_methods: {window}"
    );
}
