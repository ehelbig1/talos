//! Call-site pin: `restore_pinned_modules` rebuilds the SAME copy, from the
//! template found by the one resolver, and writes the hash with the bytes
//! (2026-09-30).
//!
//! The resolver and the id-keyed writer are tested on their own. What those
//! tests cannot see is whether the handler (a) resolves through the resolver
//! instead of joining the pinned name onto the catalog path, (b) refuses a
//! copy whose source differs from the template BEFORE compiling, and (c)
//! writes through the id-keyed writer with the shared hash function. Stated
//! as TEXTUAL: driving the handler needs the catalog compiler. It lives in
//! its own file so it can never match its own needles.

fn restore_handler_body() -> &'static str {
    let src = include_str!("modules.rs");
    let start = src
        .find(&["async fn handle_restore_pinned_", "modules("].concat())
        .expect("restore handler");
    let rest = &src[start..];
    let end = rest[1..]
        .find("\nasync fn ")
        .or_else(|| rest[1..].find("\nfn "))
        .map_or(rest.len(), |e| e + 1);
    &rest[..end]
}

#[test]
fn restore_resolves_checks_source_then_writes_by_id_with_the_hash() {
    // Whitespace removed, so rustfmt reflowing a call cannot hide a needle.
    let body: String = restore_handler_body()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let at = |needle: &[&str]| body.find(&needle.concat());
    assert!(
        at(&["catalog_dir", ".join("]).is_none(),
        "a pinned name is never joined onto the catalog path"
    );
    let read = at(&[".get_pinned_restore", "_target(user_id"]).expect("reads the copy");
    let resolve = at(&["resolve_catalog_template", "_dir(catalog_dir,key)"]).expect("resolves");
    let compare =
        at(&["rebuildable_template(&target", ".source_code,template)"]).expect("gates on source");
    let compile = at(&[".compile_catalog", "_template("]).expect("compiles");
    let write = at(&[".restore_missing_module", "_wasm(target.module_id"]).expect("writes by id");
    assert!(
        read < resolve && resolve < compare && compare < compile && compile < write,
        "read, resolve, compare, compile, write — in that order"
    );
    assert!(
        at(&["catalog_wasm_content", "_hash(&wasm_bytes)"]).is_some(),
        "hash from the shared fn"
    );
    assert!(
        body[compare..compile].contains("continue;"),
        "a differing source is refused, not compiled"
    );
}
