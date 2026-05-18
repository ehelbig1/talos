use super::{CompilationError, CompilationService};
use anyhow::Result;
use std::process::Stdio;
use tokio::process::Command;
use uuid::Uuid;

impl CompilationService {
    pub async fn analyze_code(
        &self,
        name: &str,
        source_code: &str,
    ) -> Result<Vec<CompilationError>> {
        let job_id = Uuid::new_v4();

        let (workspace, _package_name) = self
            .create_workspace(job_id, name, source_code, None)
            .await?;

        let output = Command::new("cargo")
            .arg("component")
            .arg("check")
            .arg("--message-format=json")
            .current_dir(&workspace)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

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
        tracing::info!("Analyzer returning {} errors for {}", errors.len(), name);
        Ok(errors)
    }
}
