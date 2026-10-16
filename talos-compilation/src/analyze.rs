use super::{CompilationError, CompilationService, CompileSlot};
use anyhow::{Context, Result};
use std::path::Path;
use std::time::Duration;
use uuid::Uuid;

/// The static source lint, as the platform's compile paths run it before
/// they build: `talos_module_source::lint`, read into [`CompilationError`]s.
///
/// One home. The lint itself (the forbidden patterns, the fuel advice, the
/// `secrets::get` hint, the opt-out comments) lives in `talos-module-source`
/// so the catalog's gate and the authoring lane run the very function the
/// compile does; this is the reading of its findings into the shape the
/// compile pipeline reports.
pub fn lint_source_code(source: &str) -> Vec<CompilationError> {
    talos_module_source::lint::lint(source)
        .into_iter()
        .map(|l| CompilationError {
            line: l.line.and_then(|n| i32::try_from(n).ok()),
            column: None,
            end_line: None,
            end_column: None,
            message: l.message,
            severity: l.severity.as_str().to_string(),
        })
        .collect()
}

impl CompilationService {
    pub async fn analyze_code(
        &self,
        name: &str,
        source_code: &str,
    ) -> Result<Vec<CompilationError>> {
        self.ensure_enabled()?;
        // Run static lints first (instant, no compilation needed)
        let mut lint_warnings = lint_source_code(source_code);

        // 2026-09-25: `analyze_code` spawns `cargo component check` over
        // caller-supplied source (reachable from GraphQL) and took NO compile
        // slot, so its children were outside the concurrency bound entirely.
        // It now waits for a slot like the lint path (same semaphore, same
        // 60 s wait) and every child it runs holds that slot until it is dead.
        let slot = tokio::time::timeout(Duration::from_secs(60), self.acquire_slot())
            .await
            .map_err(|_| anyhow::anyhow!("Source analysis queue full. Try again shortly."))??;

        let job_id = Uuid::new_v4();

        let (workspace, _package_name) = self
            .create_workspace(job_id, name, source_code, None)
            .await?;

        // L-37 inner/outer: the ONE cleanup below covers every exit of the
        // check. Until 2026-09-25 a timeout `?`-returned past the cleanup and
        // leaked the workspace directory.
        let result = self.analyze_in_workspace(&workspace, &slot).await;
        tokio::fs::remove_dir_all(&workspace).await.ok();
        let mut errors = result?;

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

    /// Inner analysis body — the caller owns workspace cleanup, so every
    /// early return here is leak-free.
    async fn analyze_in_workspace(
        &self,
        workspace: &Path,
        slot: &CompileSlot,
    ) -> Result<Vec<CompilationError>> {
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
        //
        // 2026-09-10: routed through `container::build_command` like every
        // other cargo spawn in this crate. Pre-fix this was a bare
        // `Command::new("cargo")` — it ran on the HOST even with the sandbox
        // enabled, inherited the controller's whole environment, and skipped
        // the production fail-closed gate that `build_command` applies. A
        // `build_command` refusal (production without a runtime and without
        // the host-fallback ack) is PROPAGATED, never worked around.
        let cargo_registry_cache = dirs_next::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join(".cargo/registry");
        let wit_dir = self
            .wit_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let mut cmd = match crate::container::build_command(
            workspace,
            &cargo_registry_cache,
            wit_dir,
            None,
        ) {
            Ok(cmd) => cmd,
            Err(e) => {
                return Err(e).context(
                    "Source analysis requires the compilation sandbox (or an explicit \
                     host-fallback opt-in); refusing to run `cargo component check` on the host",
                );
            }
        };
        cmd.arg("component")
            .arg("check")
            .arg("--message-format=json")
            .current_dir(workspace);
        let output = cmd
            .run(Duration::from_secs(30), slot)
            .await
            .map_err(|e| e.with_timeout_context("Source analysis timed out after 30 seconds"))?;

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

        Ok(errors)
    }
}

#[cfg(test)]
mod lint_reading_tests {
    use super::lint_source_code;
    use crate::lint_refuses_compile;

    /// The compile refuses exactly what `talos_module_source::lint::errors`
    /// names, so the catalog's gate and the lane's cannot pass a source the
    /// compile would refuse, or refuse one it would take.
    #[test]
    fn the_findings_that_refuse_a_compile_are_the_lints_errors() {
        let src = "#[talos_module]\nconst K: &str = env!(\"HOME\");\nunsafe { x() }\nlet v: serde_json::Value = serde_json::from_str(&body)?;";
        let refused: Vec<(Option<i32>, String)> = lint_source_code(src)
            .into_iter()
            .filter(lint_refuses_compile)
            .map(|e| (e.line, e.message))
            .collect();
        let errors: Vec<(Option<i32>, String)> = talos_module_source::lint::errors(src)
            .into_iter()
            .map(|l| (l.line.map(|n| n as i32), l.message))
            .collect();
        assert_eq!(refused, errors);
        assert_eq!(refused.len(), 2, "{refused:?}");
        assert_eq!(lint_source_code(src).len(), 4);
    }
}
