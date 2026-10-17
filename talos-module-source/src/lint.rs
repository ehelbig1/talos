//! The static lint the platform's compile paths run before they build.
//!
//! It runs before `cargo component check`, in milliseconds, and finds two
//! kinds of thing:
//!
//! * patterns the sandbox cannot honour and the compile REFUSES —
//!   `unsafe`, `extern "C"`, `std::process::`, `env!()` / `option_env!()`,
//!   `include_str!()` / `include_bytes!()` / `include!()`, `#[path = …]`, and
//!   the `secrets::get(` misspelling. Each is [`Severity::Error`]; see
//!   [`errors`];
//! * advice the compile goes on past — a `serde_json::Value` parse of an
//!   upstream payload (3–10× the fuel of a typed struct), a `#[talos_module]`
//!   with no world declared. Each is [`Severity::Warning`].
//!
//! Every finding honours an opt-out comment on its own line
//! (`// lint-allow: unsafe-code`, `// lint-allow: value-parser`, …) for the
//! rare module with a reviewed justification. The runtime still refuses a
//! sandbox escape regardless; the lint is about saying so clearly and early,
//! not about enforcement.
//!
//! One home: `talos_compilation::source_lint_errors` (what both compile paths
//! ask) and the catalog's and the authoring lane's gates all read this
//! function. The lint is told by LINE, string-literal aware within a line
//! (`find_keyword_outside_string`), and a whole line that is a comment is
//! skipped.

/// How a finding bears on the compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The compile refuses the source.
    Error,
    /// Advice; the compile goes on.
    Warning,
}

impl Severity {
    /// The word the platform's `CompilationError.severity` carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }
}

/// One finding of the lint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lint {
    /// The 1-based line, where the finding is about one.
    pub line: Option<u32>,
    /// What was found and what to do; begins with the finding's name
    /// (`forbidden-unsafe:`, `fuel-warning:`, …).
    pub message: String,
    pub severity: Severity,
}

fn at(line: Option<usize>, message: String, severity: Severity) -> Lint {
    Lint {
        line: line.map(|l| u32::try_from(l).unwrap_or(u32::MAX)),
        message,
        severity,
    }
}

/// Every finding over `source`, errors and warnings.
#[must_use]
pub fn lint(source: &str) -> Vec<Lint> {
    let mut findings = scan_forbidden_patterns(source);

    // A `#[talos_module]` with no world declared compiles for `minimal-node`
    // (no host imports): an HTTP module without the annotation fails with a
    // confusing "missing host import" rather than a clear hint.
    let has_world_decl = source.contains("world: \"") || source.contains("world = \"");
    let has_talos_macro = source.contains("#[talos_node")
        || source.contains("talos_sdk_macros::talos_node")
        || source.contains("#[talos_module")
        || source.contains("talos_sdk_macros::talos_module");
    if has_talos_macro && !has_world_decl {
        findings.push(at(
            None,
            "missing-world-annotation: this module declares a `#[talos_node]` / \
             `#[talos_module]` macro but no `world = \"...\"` is set. The compiler \
             defaults to `minimal-node` (no host imports — JSON in/out only). \
             If you need HTTP / secrets / database / etc., declare the world \
             explicitly, e.g. `#[talos_node(world = \"http-node\")]`. \
             Available worlds: minimal-node, http-node, network-node, \
             secrets-node, database-node, automation-node, agent-node."
                .to_string(),
            Severity::Warning,
        ));
    }

    // `secrets::get(` is not a function (it is `secrets::get_secret`). Rustc's
    // own "did you mean" points at `agent_memory::get` / `state::get`, which
    // are unrelated stores, so the hint is given here, before the compile.
    for (line_idx, line) in source.lines().enumerate() {
        if line.trim().starts_with("//") || !calls_secrets_get(line) {
            continue;
        }
        findings.push(at(
            Some(line_idx + 1),
            "secrets-api: `secrets::get(...)` is not a function. Use \
             `talos::core::secrets::get_secret(\"vault/path\")` — it returns a \
             slot handle (u64) that you pass to `http::fetch_with_bearer` / \
             `fetch_with_header` (Tier-1, no plaintext crosses WASM) or to \
             `secrets::expose_secret` (Tier-2, audited + rate-limited). \
             The name `get` exists on `agent_memory::` and `state::` but those \
             are unrelated stores — rustc's suggestion is misleading."
                .to_string(),
            Severity::Error,
        ));
    }

    // `serde_json::Value` parsed from an upstream payload. The engine
    // envelope (`from_str(&input)`, the `fn run` parameter) is the one place
    // a Value parse is unavoidable, and is not flagged.
    for (line_idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || line.contains("// lint-allow: value-parser") {
            continue;
        }
        let has_value_type =
            line.contains("serde_json::Value") || line.contains("from_str::<Value>");
        if !has_value_type || !line.contains("from_str") || is_envelope_parse(line) {
            continue;
        }
        findings.push(at(
            Some(line_idx + 1),
            "fuel-warning: serde_json::Value parsing is 3-10x more expensive \
             in WASM fuel than typed #[derive(serde::Deserialize)] structs. \
             Consider defining a struct for the expected input shape. \
             Add '// lint-allow: value-parser' to this line to suppress."
                .to_string(),
            Severity::Warning,
        ));
    }

    findings
}

/// The findings that refuse a compile: [`lint`] at [`Severity::Error`].
#[must_use]
pub fn errors(source: &str) -> Vec<Lint> {
    lint(source)
        .into_iter()
        .filter(|l| l.severity == Severity::Error)
        .collect()
}

/// `secrets :: get (` with any spacing, `secrets` a whole word (so
/// `my_secrets::get(` is not it) and `get` followed by `(` (so
/// `secrets::get_secret(` is not it).
fn calls_secrets_get(line: &str) -> bool {
    let b = line.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let skip_ws = |mut i: usize| {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        i
    };
    let mut from = 0;
    while let Some(found) = line[from..].find("secrets") {
        let start = from + found;
        from = start + 1;
        if start > 0 && word(b[start - 1]) {
            continue;
        }
        let mut i = skip_ws(start + "secrets".len());
        if !line[i..].starts_with("::") {
            continue;
        }
        i = skip_ws(i + 2);
        if !line[i..].starts_with("get") {
            continue;
        }
        i = skip_ws(i + 3);
        if line[i..].starts_with('(') {
            return true;
        }
    }
    false
}

/// Whitespace-tolerant detection of the engine envelope parse:
/// `from_str ( & input )` (with any spacing). The single canonical position
/// where a Value parse is unavoidable and intentional.
fn is_envelope_parse(line: &str) -> bool {
    let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    compact.contains("from_str(&input)") || compact.contains("from_str(input.as_str())")
}

/// String-literal-aware keyword search. Returns the byte offset of the first
/// occurrence of `keyword` that is NOT inside a `"..."` string literal, or
/// `None`. Treats `\"` as an escaped quote.
fn find_keyword_outside_string(line: &str, keyword: &str) -> Option<usize> {
    find_outside_string(line, keyword, false)
}

/// Like [`find_keyword_outside_string`], with a word boundary on BOTH sides:
/// `Utc::now` is found in `Utc::now()` and not in `Utc::nowish`.
pub(crate) fn find_word_outside_string(line: &str, word: &str) -> Option<usize> {
    find_outside_string(line, word, true)
}

fn find_outside_string(line: &str, keyword: &str, whole_word: bool) -> Option<usize> {
    let bytes = line.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let kbytes = keyword.as_bytes();
    let mut in_str = false;
    let mut i = 0;
    while i + kbytes.len() <= bytes.len() {
        let b = bytes[i];
        if in_str {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_str = true;
            i += 1;
            continue;
        }
        if &bytes[i..i + kbytes.len()] == kbytes {
            // A word boundary on the LEFT (so `is_unsafe` does not fire);
            // the right-hand context is the caller's.
            let left_is_word = i > 0 && is_word(bytes[i - 1]);
            let right_is_word =
                whole_word && bytes.get(i + kbytes.len()).is_some_and(|&b| is_word(b));
            if !left_is_word && !right_is_word {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// The patterns a module cannot carry into the sandbox (wasm-security-review,
/// 2026-05-22; compile-time host capture, 2026-09-10). Pure, for unit tests.
///
/// Each, on its own line and honouring its opt-out:
///   * `unsafe {` / `unsafe fn` / `unsafe trait` / `unsafe impl` /
///     `unsafe extern` — nothing in a module needs it (no FFI, no raw pointer
///     into host memory). Opt-out `// lint-allow: unsafe-code`.
///   * `extern "C"` — FFI; links in WASM and then traps. Opt-out
///     `// lint-allow: extern-c`. `extern crate x;` is allowed.
///   * `std::process::` — no fork/exec in WASIp2. Opt-out
///     `// lint-allow: std-process`.
///   * `env!(` / `option_env!(` — captures the BUILD HOST's environment into
///     the module bytes. Opt-out `// lint-allow: build-env`.
///   * `include_str!(` / `include_bytes!(` / `include!(` — reads the build
///     host's filesystem into the module. Opt-out `// lint-allow: include-file`.
///   * `#[path = "..."]` — the same host-file read with a module wrapper.
///     Opt-out `// lint-allow: path-attr`.
#[must_use]
pub fn scan_forbidden_patterns(source: &str) -> Vec<Lint> {
    let mut out = Vec::new();
    for (idx, line) in source.lines().enumerate() {
        let line_no = Some(idx + 1);
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }

        if let Some(pos) = find_keyword_outside_string(line, "unsafe") {
            let after = line[pos + "unsafe".len()..].trim_start();
            let starts_real = after.starts_with('{')
                || after.starts_with("fn ")
                || after.starts_with("fn\t")
                || after.starts_with("trait ")
                || after.starts_with("trait\t")
                || after.starts_with("impl ")
                || after.starts_with("impl\t")
                || after.starts_with("extern");
            if starts_real && !line.contains("// lint-allow: unsafe-code") {
                out.push(at(
                    line_no,
                    "forbidden-unsafe: `unsafe` blocks/items are not permitted in WASM \
                     modules. There is no FFI, no raw-pointer escape, and no syscall \
                     surface that requires `unsafe` from guest code. If you have a \
                     documented justification, add `// lint-allow: unsafe-code` to \
                     this line."
                        .to_string(),
                    Severity::Error,
                ));
            }
        }

        if let Some(pos) = find_keyword_outside_string(line, "extern") {
            let after = line[pos + "extern".len()..].trim_start();
            if after.starts_with('"') && !line.contains("// lint-allow: extern-c") {
                out.push(at(
                    line_no,
                    "forbidden-extern: `extern \"...\"` FFI declarations are not \
                     permitted in WASM modules. Host functions are reached through \
                     the typed WIT interfaces (talos::core::*), not raw FFI. If you \
                     have a documented justification, add `// lint-allow: extern-c` \
                     to this line."
                        .to_string(),
                    Severity::Error,
                ));
            }
        }

        if find_keyword_outside_string(line, "std::process::").is_some()
            && !line.contains("// lint-allow: std-process")
        {
            out.push(at(
                line_no,
                "forbidden-process: `std::process::*` is not available in WASM \
                 modules — there is no fork/exec/spawn surface in WASIp2 and the \
                 talos worker does not bind any process-control host functions. \
                 If you need to invoke another module, use the workflow engine's \
                 subworkflow / chain-dispatch primitives instead. If you have a \
                 documented justification, add `// lint-allow: std-process` to \
                 this line."
                    .to_string(),
                Severity::Error,
            ));
        }

        // `find_keyword_outside_string` requires a non-word char on the LEFT,
        // so `option_env!` does NOT double-fire the `env!` arm (the `_` before
        // `env` is a word char) and `my_env!` is not matched.
        for kw in ["env!", "option_env!"] {
            if find_keyword_outside_string(line, kw).is_some()
                && !line.contains("// lint-allow: build-env")
            {
                out.push(at(
                    line_no,
                    format!(
                        "forbidden-build-env: `{kw}(...)` captures the BUILD HOST's environment \
                         at compile time. The module is compiled on the controller (or in its \
                         sandbox), so this would bake controller-side configuration or \
                         credentials into the module bytes. Runtime configuration reaches a \
                         module through its `config` input; secrets through \
                         `talos::core::secrets`. If you have a documented justification, add \
                         `// lint-allow: build-env` to this line."
                    ),
                    Severity::Error,
                ));
                break;
            }
        }

        for kw in ["include_str!", "include_bytes!", "include!"] {
            if find_keyword_outside_string(line, kw).is_some()
                && !line.contains("// lint-allow: include-file")
            {
                out.push(at(
                    line_no,
                    format!(
                        "forbidden-include: `{kw}(...)` reads a file from the BUILD HOST's \
                         filesystem into the module at compile time. A module is a single \
                         source file; there is nothing legitimate for it to embed, and the \
                         path resolves on the controller. If you have a documented \
                         justification, add `// lint-allow: include-file` to this line."
                    ),
                    Severity::Error,
                ));
                break;
            }
        }

        if let Some(pos) = find_keyword_outside_string(line, "#[path") {
            let after = line[pos + "#[path".len()..].trim_start();
            if after.starts_with('=') && !line.contains("// lint-allow: path-attr") {
                out.push(at(
                    line_no,
                    "forbidden-path-attr: `#[path = \"...\"]` points a module at an \
                     arbitrary file on the BUILD HOST. A module is a single source file. \
                     If you have a documented justification, add `// lint-allow: path-attr` \
                     to this line."
                        .to_string(),
                    Severity::Error,
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod forbidden_pattern_tests {
    use super::{scan_forbidden_patterns, Severity};

    fn err_msgs(source: &str) -> Vec<String> {
        scan_forbidden_patterns(source)
            .into_iter()
            .filter(|e| e.severity == Severity::Error)
            .map(|e| e.message)
            .collect()
    }

    #[test]
    fn flags_unsafe_block() {
        let errs = err_msgs("fn run() { unsafe { do_thing(); } }");
        assert!(errs.iter().any(|m| m.contains("forbidden-unsafe")));
    }

    #[test]
    fn flags_unsafe_fn() {
        let errs = err_msgs("unsafe fn dangerous() {}");
        assert!(errs.iter().any(|m| m.contains("forbidden-unsafe")));
    }

    #[test]
    fn allows_unsafe_in_string_literal() {
        let errs = err_msgs(r#"let s = "unsafe { x }";"#);
        assert!(errs.iter().all(|m| !m.contains("forbidden-unsafe")));
    }

    #[test]
    fn allows_identifier_containing_unsafe() {
        let errs = err_msgs("let is_unsafe = true;");
        assert!(errs.iter().all(|m| !m.contains("forbidden-unsafe")));
    }

    #[test]
    fn honours_unsafe_opt_out() {
        let errs = err_msgs("unsafe { real(); } // lint-allow: unsafe-code");
        assert!(errs.iter().all(|m| !m.contains("forbidden-unsafe")));
    }

    #[test]
    fn flags_extern_c() {
        let errs = err_msgs(r#"extern "C" { fn malloc(n: usize) -> *mut u8; }"#);
        assert!(errs.iter().any(|m| m.contains("forbidden-extern")));
    }

    #[test]
    fn flags_extern_system() {
        let errs = err_msgs(r#"extern "system" fn whatever() {}"#);
        assert!(errs.iter().any(|m| m.contains("forbidden-extern")));
    }

    #[test]
    fn allows_extern_crate() {
        let errs = err_msgs("extern crate something;");
        assert!(errs.iter().all(|m| !m.contains("forbidden-extern")));
    }

    #[test]
    fn honours_extern_opt_out() {
        let errs = err_msgs(r#"extern "C" { fn x(); } // lint-allow: extern-c"#);
        assert!(errs.iter().all(|m| !m.contains("forbidden-extern")));
    }

    #[test]
    fn flags_std_process() {
        let errs = err_msgs("let out = std::process::Command::new(\"ls\");");
        assert!(errs.iter().any(|m| m.contains("forbidden-process")));
    }

    #[test]
    fn allows_std_process_in_string() {
        let errs = err_msgs(r#"let s = "look at std::process::Command";"#);
        assert!(errs.iter().all(|m| !m.contains("forbidden-process")));
    }

    #[test]
    fn honours_std_process_opt_out() {
        let errs =
            err_msgs("let out = std::process::Command::new(\"ls\"); // lint-allow: std-process");
        assert!(errs.iter().all(|m| !m.contains("forbidden-process")));
    }

    #[test]
    fn skips_line_comments() {
        let errs = err_msgs("// example: unsafe { x }");
        assert!(errs.is_empty());
    }

    #[test]
    fn flags_env_macro_and_option_env_and_concat_env() {
        for src in [
            r#"const K: &str = env!("TALOS_MASTER_KEY");"#,
            r#"const K: Option<&str> = option_env!("WORKER_SHARED_KEY");"#,
            r#"const K: &str = concat!(env!("DATABASE_URL"), "/x");"#,
            r#"let k = std::env!("HOME");"#,
        ] {
            let errs = err_msgs(src);
            assert_eq!(
                errs.iter()
                    .filter(|m| m.contains("forbidden-build-env"))
                    .count(),
                1,
                "{src} → {errs:?}"
            );
        }
    }

    #[test]
    fn flags_include_macros() {
        for src in [
            r#"const S: &str = include_str!("../../.env");"#,
            r#"const B: &[u8] = include_bytes!("/etc/talos/master.key");"#,
            r#"include!("/etc/passwd");"#,
        ] {
            let errs = err_msgs(src);
            assert_eq!(
                errs.iter()
                    .filter(|m| m.contains("forbidden-include"))
                    .count(),
                1,
                "{src} → {errs:?}"
            );
        }
    }

    #[test]
    fn flags_path_attribute() {
        let errs = err_msgs(r#"#[path = "/etc/talos/secrets.rs"] mod leak;"#);
        assert!(errs.iter().any(|m| m.contains("forbidden-path-attr")));
        let errs = err_msgs(r#"#[path="../../x.rs"] mod leak;"#);
        assert!(errs.iter().any(|m| m.contains("forbidden-path-attr")));
    }

    #[test]
    fn host_capture_lints_respect_string_literals_and_comments() {
        for src in [
            r#"let s = "call env!(\"X\") here";"#,
            r#"let s = "docs mention include_str!(...)";"#,
            r##"let s = "#[path = \"x\"]";"##,
            "// env!(\"X\") in a comment",
            "// include_bytes!(\"x\") in a comment",
        ] {
            let errs = err_msgs(src);
            assert!(
                errs.iter().all(|m| {
                    !m.contains("forbidden-build-env")
                        && !m.contains("forbidden-include")
                        && !m.contains("forbidden-path-attr")
                }),
                "{src} → {errs:?}"
            );
        }
    }

    #[test]
    fn host_capture_lints_do_not_fire_on_runtime_env_or_similar_names() {
        let errs = err_msgs(r#"let v = std::env::var("X");"#);
        assert!(errs.iter().all(|m| !m.contains("forbidden-build-env")));
        let errs = err_msgs("my_env!(x); reinclude!(y); path = 3;");
        assert!(errs.iter().all(|m| {
            !m.contains("forbidden-build-env")
                && !m.contains("forbidden-include")
                && !m.contains("forbidden-path-attr")
        }));
    }

    #[test]
    fn honours_host_capture_opt_outs() {
        let errs = err_msgs(r#"const K: &str = env!("X"); // lint-allow: build-env"#);
        assert!(errs.iter().all(|m| !m.contains("forbidden-build-env")));
        let errs = err_msgs(r#"const S: &str = include_str!("x"); // lint-allow: include-file"#);
        assert!(errs.iter().all(|m| !m.contains("forbidden-include")));
        let errs = err_msgs(r#"#[path = "x.rs"] mod m; // lint-allow: path-attr"#);
        assert!(errs.iter().all(|m| !m.contains("forbidden-path-attr")));
    }
}

#[cfg(test)]
mod lint_tests {
    use super::*;

    #[test]
    fn the_secrets_get_misspelling_is_an_error_and_the_right_call_is_not() {
        for src in [
            "let h = secrets::get(\"a/b\");",
            "let h = secrets :: get (\"a/b\");",
            "talos::core::secrets::get(\"a/b\")",
        ] {
            let e = errors(src);
            assert!(
                e.len() == 1 && e[0].message.starts_with("secrets-api:") && e[0].line == Some(1),
                "{src} → {e:?}"
            );
        }
        for src in [
            "let h = secrets::get_secret(\"a/b\");",
            "let h = my_secrets::get(\"a/b\");",
            "// secrets::get(\"a/b\")",
            "let h = secrets::getter(\"a/b\");",
        ] {
            assert!(errors(src).is_empty(), "{src}");
        }
    }

    #[test]
    fn a_value_parse_of_a_payload_is_advice_and_the_envelope_is_not() {
        let advice = lint("let v: serde_json::Value = serde_json::from_str(&body)?;");
        assert!(
            advice.len() == 1
                && advice[0].severity == Severity::Warning
                && advice[0].message.starts_with("fuel-warning:"),
            "{advice:?}"
        );
        assert!(errors("let v: serde_json::Value = serde_json::from_str(&body)?;").is_empty());
        for ok in [
            "let v: serde_json::Value = serde_json::from_str(&input)?;",
            "let v: serde_json::Value = serde_json::from_str( input.as_str() )?;",
            "let v: serde_json::Value = serde_json::from_str(&body)?; // lint-allow: value-parser",
        ] {
            assert!(lint(ok).is_empty(), "{ok}");
        }
    }

    #[test]
    fn a_module_macro_without_a_world_is_advice() {
        let l = lint("#[talos_module]\npub fn run(i: String) -> Result<String, String> { Ok(i) }");
        assert!(
            l.len() == 1
                && l[0].line.is_none()
                && l[0].message.starts_with("missing-world-annotation:")
        );
        assert!(lint("#[talos_module(world = \"http-node\")]\npub fn run() {}").is_empty());
        assert!(
            lint("pub fn run(input: String) -> Result<String, String> { Ok(input) }").is_empty()
        );
    }

    #[test]
    fn errors_are_exactly_the_findings_that_refuse_a_compile() {
        let src = "#[talos_module]\nconst K: &str = env!(\"HOME\");\nlet v: serde_json::Value = serde_json::from_str(&body)?;";
        let all = lint(src);
        assert_eq!(all.len(), 3);
        let e = errors(src);
        assert!(
            e.len() == 1 && e[0].message.starts_with("forbidden-build-env") && e[0].line == Some(2)
        );
    }
}
