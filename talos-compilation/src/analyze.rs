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
