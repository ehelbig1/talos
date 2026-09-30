//! Call-site pin: `install_module_from_catalog` writes the grants the ONE
//! install-grant rule decided, and refuses when it cannot read the installed
//! copy's grants (2026-09-29).
//!
//! `grants_for_install` is unit-tested in `modules.rs`. What a test of the
//! function cannot see is whether the handler (a) reads the installed copy's
//! grants at all, (b) refuses on an unreadable read instead of proceeding,
//! and (c) passes the RESULT, not the template's grant, to the writer — a
//! handler that computed the carried grants and then wrote the template's
//! would leave every unit test green while undoing every narrowing on
//! reinstall. Stated as TEXTUAL: driving the handler needs the catalog
//! compiler. It lives in its own file so it can never match its own needles.

fn install_handler_body() -> &'static str {
    let src = include_str!("modules.rs");
    let start = src
        .find(&["async fn handle_install_module_from_catalog", "("].concat())
        .expect("install handler");
    let rest = &src[start..];
    // The handler ends where the next top-level item begins.
    let end = rest[1..]
        .find("\nasync fn ")
        .or_else(|| rest[1..].find("\npub"))
        .map_or(rest.len(), |e| e + 1);
    &rest[..end]
}

#[test]
fn the_install_handler_reads_carries_and_writes_the_carried_grants() {
    let body = install_handler_body();
    let read = [".get_user_module_grants", "(user_id, &display_name)"].concat();
    assert_eq!(
        body.matches(&read).count(),
        1,
        "reads the installed copy's grants"
    );
    let decide = ["grants_for_install", "("].concat();
    assert_eq!(
        body.matches(&decide).count(),
        1,
        "decides through the one rule"
    );
    let decided = &body[body.find(&decide).expect("decision")..];
    let first_arg = decided[decide.len()..].trim_start();
    assert!(
        first_arg.starts_with(&["installed_copy", ".as_ref(),"].concat()),
        "the rule is given the installed copy, not None: {}",
        &first_arg[..first_arg.len().min(60)]
    );

    // The read's error arm returns before anything is written.
    let read_at = body.find(&read).expect("read");
    let err_arm =
        &body[read_at..read_at + body[read_at..].find(&decide).expect("decision after read")];
    assert!(
        err_arm.contains(&["Err(", "e) =>"].concat())
            && err_arm.contains(&["return mcp_", "error("].concat())
    );

    // The writer receives the rule's bindings, which shadow the template's.
    let destructure = ["hosts: ", "allowed_hosts,"].concat();
    assert!(
        body.contains(&destructure),
        "the rule's result is bound to the names the writer takes"
    );
    let write_at = body
        .find(&[".install_catalog_module_to_", "modules("].concat())
        .expect("writer");
    assert!(
        body.find(&decide).expect("decision") < write_at,
        "decided before the write"
    );
    let write = &body[write_at..write_at + 800.min(body.len() - write_at)];
    for g in ["&allowed_hosts,", "&allowed_methods,", "&allowed_secrets,"] {
        assert!(write.contains(g), "writer takes {g}");
    }
}
