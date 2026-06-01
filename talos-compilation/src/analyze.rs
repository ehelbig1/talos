use super::{CompilationError, CompilationService};
use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::process::Command;
use uuid::Uuid;

/// Static source-level lint that detects known WASM fuel anti-patterns.
///
/// Runs before `cargo component check` — zero compilation overhead.
/// Honors `// lint-allow: value-parser` inline opt-out comments.
///
/// SUPPRESSED PATTERNS (recognized as the documented engine envelope, NOT
/// the anti-pattern this lint targets):
///   * `let data: serde_json::Value = serde_json::from_str(&input)` — the
///     scaffold's canonical envelope parse where `input` is the `fn run`
///     parameter (a String containing `{config, input, ...}`). Parsing the
///     envelope as Value is necessary because `config`/`input` keys are
///     dynamic; the FUEL cost concern targets parsing UPSTREAM payloads
///     (HTTP responses, files, etc.), not the engine envelope.
pub fn lint_source_code(source: &str) -> Vec<CompilationError> {
    let mut warnings = Vec::new();

    // wasm-security-review (2026-05-22): pre-pass for sandbox-escape
    // patterns that aren't natively reachable from WASM (no syscalls,
    // no fork/exec, no FFI runtime) but cause confusing rustc errors
    // and waste a 60s compile slot when an unfamiliar module author
    // tries them. Detecting at the lint layer emits a clear "not
    // permitted" message instead of "linker error: cannot find
    // symbol fork@@GLIBC". Each pattern below is tied to a specific
    // forbidden class.
    //
    // Each check honours an inline opt-out comment on the matched
    // line (`// lint-allow: unsafe-code`, etc.) for the rare module
    // that has a documented justification reviewed by an operator.
    // The runtime still rejects sandbox escapes regardless — these
    // lints are about UX clarity, not enforcement.
    warnings.extend(scan_forbidden_patterns(source));

    // Pre-pass: warn when no WIT world declaration is found in source.
    // Without an explicit `world = "..."` annotation, the scaffold falls
    // back to TALOS_DEFAULT_WIT_WORLD (default `minimal-node`), which is
    // intentionally minimal-privilege. If the author intended an HTTP
    // module but forgot the annotation, compilation fails with a
    // confusing "missing host import" error rather than a clear hint.
    // Surface the missing annotation here so the fix is obvious.
    //
    // Skip the warning when the source declares either `world: "..."` or
    // `world = "..."` (matches `extract_wit_world` semantics) OR when no
    // talos macro/proc-macro is present (someone is linting a helper
    // file, not a module entry point).
    let has_world_decl = source.contains("world: \"") || source.contains("world = \"");
    let has_talos_macro = source.contains("#[talos_node")
        || source.contains("talos_sdk_macros::talos_node")
        || source.contains("#[talos_module")
        || source.contains("talos_sdk_macros::talos_module");
    if has_talos_macro && !has_world_decl {
        warnings.push(CompilationError {
            line: None,
            column: None,
            end_line: None,
            end_column: None,
            message: "missing-world-annotation: this module declares a `#[talos_node]` / \
                      `#[talos_module]` macro but no `world = \"...\"` is set. The compiler \
                      defaults to `minimal-node` (no host imports — JSON in/out only). \
                      If you need HTTP / secrets / database / etc., declare the world \
                      explicitly, e.g. `#[talos_node(world = \"http-node\")]`. \
                      Available worlds: minimal-node, http-node, network-node, \
                      secrets-node, database-node, automation-node, agent-node."
                .to_string(),
            severity: "warning".to_string(),
        });
    }

    // Pre-pass: detect `secrets::get(` (the wrong name — should be
    // `secrets::get_secret`). Rustc's own "did you mean" suggests
    // `agent_memory::get` / `state::get` because those are the similarly-named
    // items in scope, sending the author down the wrong path. Catch it here
    // and emit the correct hint before paying the 30–60 s compile.
    static RE_SECRETS_GET_TYPO: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"\bsecrets\s*::\s*get\s*\(").unwrap());
    for (line_idx, line) in source.lines().enumerate() {
        if line.trim().starts_with("//") {
            continue;
        }
        if !RE_SECRETS_GET_TYPO.is_match(line) {
            continue;
        }
        // Don't fire on the correct `secrets::get_secret(` — the regex above
        // matches `secrets::get(` (open-paren immediately after `get`), so
        // `get_secret(` is excluded by construction.
        warnings.push(CompilationError {
            line: Some((line_idx + 1) as i32),
            column: None,
            end_line: None,
            end_column: None,
            message: "secrets-api: `secrets::get(...)` is not a function. Use \
                      `talos::core::secrets::get_secret(\"vault/path\")` — it returns a \
                      slot handle (u64) that you pass to `http::fetch_with_bearer` / \
                      `fetch_with_header` (Tier-1, no plaintext crosses WASM) or to \
                      `secrets::expose_secret` (Tier-2, audited + rate-limited). \
                      The name `get` exists on `agent_memory::` and `state::` but those \
                      are unrelated stores — rustc's suggestion is misleading."
                .to_string(),
            severity: "error".to_string(),
        });
    }

    for (line_idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();

        // Skip comment-only lines and lines with explicit opt-out
        if trimmed.starts_with("//") || line.contains("// lint-allow: value-parser") {
            continue;
        }

        // Detect serde_json::Value used with from_str on upstream payload data.
        // Pattern 1: `let data: serde_json::Value = serde_json::from_str(...)`
        // Pattern 2: `serde_json::from_str::<serde_json::Value>(...)`
        // Pattern 3: `from_str::<Value>(...)`
        let has_value_type =
            line.contains("serde_json::Value") || line.contains("from_str::<Value>");
        let has_from_str = line.contains("from_str");

        if !has_value_type || !has_from_str {
            continue;
        }

        // Suppress: envelope pattern. `from_str(&input)` is parsing the `fn run`
        // function parameter — this is the documented engine envelope shape.
        // The targeted anti-pattern is `from_str(&body)` / `from_str(&resp)` /
        // any non-`input` source where a typed struct would be cheaper.
        if is_envelope_parse(line) {
            continue;
        }

        warnings.push(CompilationError {
            line: Some((line_idx + 1) as i32),
            column: None,
            end_line: None,
            end_column: None,
            message: "fuel-warning: serde_json::Value parsing is 3-10x more expensive \
                      in WASM fuel than typed #[derive(serde::Deserialize)] structs. \
                      Consider defining a struct for the expected input shape. \
                      Add '// lint-allow: value-parser' to this line to suppress."
                .to_string(),
            severity: "warning".to_string(),
        });
    }

    warnings
}

/// wasm-security-review (2026-05-22): emit a clear "not permitted in
/// WASM modules" lint when source uses a pattern that cannot work in
/// the sandbox. Pure function for unit testing.
///
/// Patterns checked (each on its own line, honouring opt-outs):
///   * `unsafe {` block / `unsafe fn` — there's no legitimate need
///     for `unsafe` in WASM module source (no FFI, no raw pointers
///     into host memory). Opt-out: `// lint-allow: unsafe-code`.
///   * `extern "C"` — FFI declaration. Resolves at link time in
///     WASM, but the most common follow-on is a syscall attempt
///     that links cleanly and then fails at runtime with a host-
///     trap. Opt-out: `// lint-allow: extern-c`.
///   * `std::process::` — fork/exec/spawn paths. Not available in
///     WASIp2 (the talos worker doesn't bind any `wasi:process` /
///     `wasi:cli/run` interfaces). Compile fails with a confusing
///     "cannot find function `Command::new` in module `process`"
///     when the std feature isn't even compiled in. Opt-out:
///     `// lint-allow: std-process`.
///
/// Each lint suppresses on lines that are line-comments or contain
/// the opt-out marker. String literals containing the keyword (e.g.
/// `"unsafe { ... }"`) are skipped via `is_inside_string_literal`.
pub(crate) fn scan_forbidden_patterns(source: &str) -> Vec<CompilationError> {
    let mut out = Vec::new();
    for (idx, line) in source.lines().enumerate() {
        let line_no = (idx + 1) as i32;
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }

        // 1. unsafe { … } / unsafe fn / unsafe trait / unsafe impl
        //    — but NOT `pub unsafe fn` from a doc comment or a string.
        if let Some(pos) = find_keyword_outside_string(line, "unsafe") {
            // Must be a "real" unsafe — followed by `{`, `fn`, `trait`,
            // `impl`, or `extern`. This avoids matching `is_unsafe` or
            // identifiers that contain the substring.
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
                out.push(CompilationError {
                    line: Some(line_no),
                    column: None,
                    end_line: None,
                    end_column: None,
                    message: "forbidden-unsafe: `unsafe` blocks/items are not permitted in WASM \
                         modules. There is no FFI, no raw-pointer escape, and no syscall \
                         surface that requires `unsafe` from guest code. If you have a \
                         documented justification, add `// lint-allow: unsafe-code` to \
                         this line."
                        .to_string(),
                    severity: "error".to_string(),
                });
            }
        }

        // 2. extern "C" / extern "system" / extern "Rust"
        //    Allow `extern crate xyz;` (no string literal after extern).
        if let Some(pos) = find_keyword_outside_string(line, "extern") {
            let after = line[pos + "extern".len()..].trim_start();
            if after.starts_with('"') && !line.contains("// lint-allow: extern-c") {
                out.push(CompilationError {
                    line: Some(line_no),
                    column: None,
                    end_line: None,
                    end_column: None,
                    message: "forbidden-extern: `extern \"...\"` FFI declarations are not \
                         permitted in WASM modules. Host functions are reached through \
                         the typed WIT interfaces (talos::core::*), not raw FFI. If you \
                         have a documented justification, add `// lint-allow: extern-c` \
                         to this line."
                        .to_string(),
                    severity: "error".to_string(),
                });
            }
        }

        // 3. std::process::… — Command, Stdio, spawn, exit, etc.
        if find_keyword_outside_string(line, "std::process::").is_some()
            && !line.contains("// lint-allow: std-process")
        {
            out.push(CompilationError {
                line: Some(line_no),
                column: None,
                end_line: None,
                end_column: None,
                message: "forbidden-process: `std::process::*` is not available in WASM \
                     modules — there is no fork/exec/spawn surface in WASIp2 and the \
                     talos worker does not bind any process-control host functions. \
                     If you need to invoke another module, use the workflow engine's \
                     subworkflow / chain-dispatch primitives instead. If you have a \
                     documented justification, add `// lint-allow: std-process` to \
                     this line."
                    .to_string(),
                severity: "error".to_string(),
            });
        }
    }
    out
}

/// String-literal-aware keyword search. Returns the byte offset of
/// the first occurrence of `keyword` that is NOT inside a `"..."`
/// string literal, or `None`. Treats `\"` as escaped quote.
fn find_keyword_outside_string(line: &str, keyword: &str) -> Option<usize> {
    let bytes = line.as_bytes();
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
            // Require word boundary on the LEFT (so `is_unsafe`
            // doesn't fire). Right-side context is up to the caller.
            let left_is_word =
                i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            if !left_is_word {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Whitespace-tolerant detection of the engine envelope parse:
/// `from_str ( & input )` (with any spacing). The single canonical
/// position where Value parsing is unavoidable + intentional.
fn is_envelope_parse(line: &str) -> bool {
    // Strip whitespace inside the call to handle `from_str ( &input )` etc.
    let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    compact.contains("from_str(&input)") || compact.contains("from_str(input.as_str())")
}

impl CompilationService {
    pub async fn analyze_code(
        &self,
        name: &str,
        source_code: &str,
    ) -> Result<Vec<CompilationError>> {
        // Run static lints first (instant, no compilation needed)
        let mut lint_warnings = lint_source_code(source_code);

        let job_id = Uuid::new_v4();

        let (workspace, _package_name) = self
            .create_workspace(job_id, name, source_code, None)
            .await?;

        // MCP-744 (2026-05-13): cap `cargo component check` at 30s.
        // Pre-fix this Command::new(...).output().await ran unbounded —
        // pathological untrusted source (infinite macro expansion,
        // recursive type, malformed proc-macro that hangs rustc) would
        // park the GraphQL task slot indefinitely. `analyze_code` is
        // reachable from `talos-api/src/schema/workflows/queries.rs`
        // (Rhai / Rust source analysis), and the input is caller-
        // supplied. Mirrors the canonical pattern around
        // `talos-compilation/src/lib.rs:563` (cargo audit, 30s) and
        // `lib.rs:670` (cargo component build, 60s). Check is faster
        // than build → 30s matches audit. Timeout error wraps via
        // `.context(...)` so the GraphQL error mapping retains an
        // operator-readable reason without leaking source-code detail.
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            Command::new("cargo")
                .arg("component")
                .arg("check")
                .arg("--message-format=json")
                .current_dir(&workspace)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output(),
        )
        .await
        .context("Source analysis timed out after 30 seconds")??;

        let mut errors = Vec::new();

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(msg) = json.get("message") {
                    // cargo component might wrap it in an inner object?
                    // actually `msg` IS the inner object for "reason":"compiler-message"
                    // wait, no, "message":{"rendered":"...","$message_type":"diagnostic","children":[],"level":"error","message":"mismatched types","spans":[{...}]}

                    if let Some(level) = msg.get("level").and_then(|l| l.as_str()) {
                        if level == "error" || level == "warning" {
                            // Attempt to get the rendered string (includes file/line context), fallback to just message
                            let text = msg
                                .get("rendered")
                                .and_then(|r| r.as_str())
                                .unwrap_or_else(|| {
                                    msg.get("message")
                                        .and_then(|m| m.as_str())
                                        .unwrap_or("Unknown error")
                                })
                                .to_string();

                            let mut line_num = None;
                            let mut column_num = None;
                            let mut end_line = None;
                            let mut end_column = None;

                            if let Some(spans) = msg.get("spans").and_then(|s| s.as_array()) {
                                for span in spans {
                                    if span
                                        .get("is_primary")
                                        .and_then(|p| p.as_bool())
                                        .unwrap_or(false)
                                    {
                                        if let Some(file_name) =
                                            span.get("file_name").and_then(|f| f.as_str())
                                        {
                                            line_num = span
                                                .get("line_start")
                                                .and_then(|l| l.as_i64())
                                                .map(|l| l as i32);
                                            column_num = span
                                                .get("column_start")
                                                .and_then(|c| c.as_i64())
                                                .map(|c| c as i32);
                                            end_line = span
                                                .get("line_end")
                                                .and_then(|l| l.as_i64())
                                                .map(|l| l as i32);
                                            end_column = span
                                                .get("column_end")
                                                .and_then(|c| c.as_i64())
                                                .map(|c| c as i32);
                                            // Prefer src/lib.rs but accept anything
                                            if file_name.ends_with("src/lib.rs")
                                                || file_name.ends_with("src\\lib.rs")
                                            {
                                                break;
                                            }
                                        }
                                    }
                                }
                            }

                            errors.push(CompilationError {
                                line: line_num,
                                column: column_num,
                                end_line,
                                end_column,
                                message: text,
                                severity: level.to_string(),
                            });
                        }
                    }
                }
            }
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        if errors.is_empty() && !output.status.success() && !stderr.trim().is_empty() {
            errors.push(CompilationError {
                line: None,
                column: None,
                end_line: None,
                end_column: None,
                message: stderr.to_string(),
                severity: "error".to_string(),
            });
        }

        tokio::fs::remove_dir_all(&workspace).await.ok();

        // Prepend lint warnings to compiler diagnostics
        lint_warnings.append(&mut errors);
        let all = lint_warnings;

        tracing::info!(
            "Analyzer returning {} diagnostics ({} lint warnings) for {}",
            all.len(),
            all.iter().filter(|e| e.severity == "warning").count(),
            name
        );
        Ok(all)
    }
}

#[cfg(test)]
mod forbidden_pattern_tests {
    use super::scan_forbidden_patterns;

    fn err_msgs(source: &str) -> Vec<String> {
        scan_forbidden_patterns(source)
            .into_iter()
            .filter(|e| e.severity == "error")
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
        // `is_unsafe`, `marked_unsafe`, etc. must not fire — the
        // word-boundary check on the LEFT prevents this.
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
}
