#![allow(
    clippy::needless_borrows_for_generic_args,
    dead_code,
    unused_imports,
    unused_mut,
    unused_variables
)]
use anyhow::{bail, Context, Result};
use handlebars::Handlebars;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
mod analyze;
use std::path::PathBuf;
use tokio::process::Command;
use uuid::Uuid;
use worker::CapabilityWorld;

pub struct CompilationService {
    workspace_root: PathBuf,
    wit_path: PathBuf,
}

impl CompilationService {
    pub fn new(workspace_root: PathBuf) -> Self {
        // Determine WIT file path relative to the workspace
        let wit_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or_else(|| std::path::Path::new(".."))
            .join("wit/talos.wit");

        Self {
            workspace_root,
            wit_path,
        }
    }

    /// Render template with config (if it contains Handlebars syntax)
    /// Security: Uses strict Handlebars mode with HTML escaping enabled
    fn render_template(&self, template: &str, config: &serde_json::Value) -> Result<String> {
        // Fix WIT path: templates use "../wit/talos.wit" but we copy to "./wit/talos.wit"
        // This ensures proper path resolution during compilation
        let template =
            template.replace(r#"path: "../wit/talos.wit""#, r#"path: "./wit/talos.wit""#);

        // Check if template contains Handlebars syntax
        if !template.contains("{{") && !template.contains("}}") {
            // No templating needed - return as-is
            return Ok(template.to_string());
        }

        let mut handlebars = Handlebars::new();

        // SECURITY: Enable strict mode to prevent arbitrary property access
        handlebars.set_strict_mode(true);

        // SECURITY: Disable HTML escaping for code generation (we're generating Rust, not HTML)
        // but validate that config values don't contain malicious code
        self.validate_config_values(config)?;

        // Register template
        handlebars
            .register_template_string("node_template", &template)
            .context("Failed to parse Handlebars template")?;

        // Render with config
        let rendered = handlebars
            .render("node_template", config)
            .context("Failed to render template")?;

        Ok(rendered)
    }

    /// Validate WASM module structure
    /// Security: Ensures the compiled WASM is valid before storing
    fn validate_wasm(&self, wasm_bytes: &[u8]) -> Result<()> {
        // Check WASM magic number: \0asm (0x00 0x61 0x73 0x6d)
        if wasm_bytes.len() < 4 {
            bail!("WASM module too small to be valid");
        }

        if &wasm_bytes[0..4] != b"\0asm" {
            bail!("Invalid WASM magic number - not a valid WebAssembly module");
        }

        // Check version
        if wasm_bytes.len() < 8 {
            bail!("WASM module header incomplete");
        }

        let version =
            u32::from_le_bytes([wasm_bytes[4], wasm_bytes[5], wasm_bytes[6], wasm_bytes[7]]);

        // Accept both Core WASM (version 1) and Component Model WASM (various versions)
        // Component Model WASM uses different version encodings (e.g., 0x0d, 0x10001, etc.)
        // We validate the magic number here; wasmtime will do full validation at runtime
        match version {
            1 => eprintln!("✅ WASM validation passed: Core WASM module (version 1)"),
            _ if version < 100_000_000 => eprintln!(
                "✅ WASM validation passed: Component Model WASM (version {})",
                version
            ),
            _ => bail!("Invalid WASM version: {} (suspiciously large)", version),
        }

        Ok(())
    }

    /// Validate config values to prevent code injection
    /// Security: Ensures config values are safe for code generation
    fn validate_config_values(&self, config: &serde_json::Value) -> Result<()> {
        match config {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    // Recursively validate nested objects
                    self.validate_config_values(value)?;

                    // Validate key doesn't contain suspicious characters
                    if key.contains("{{") || key.contains("}}") || key.contains("${") {
                        bail!(
                            "Config key '{}' contains potentially unsafe characters",
                            key
                        );
                    }
                }
            }
            serde_json::Value::String(s) => {
                // SECURITY: Prevent nested template injection
                if s.contains("{{") || s.contains("}}") {
                    bail!(
                        "Config value contains Handlebars syntax which is not allowed: {}",
                        s
                    );
                }

                // SECURITY: Prevent command injection in generated code
                if s.contains("`;") || s.contains("${") || s.contains("$(") {
                    bail!(
                        "Config value contains potentially unsafe command injection characters: {}",
                        s
                    );
                }

                // SECURITY: Prevent CRLF/newline injection that could break generated Rust source
                if s.contains('\n') || s.contains('\r') {
                    bail!(
                        "Config value contains newline characters which are not allowed in generated code"
                    );
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    self.validate_config_values(item)?;
                }
            }
            _ => {} // Numbers, booleans, null are safe
        }
        Ok(())
    }

    /// Compile Rust source to WASM (with optional template rendering)
    pub async fn compile_to_wasm(
        &self,
        name: &str,
        source_code: &str,
    ) -> Result<CompilationResult> {
        self.compile_to_wasm_with_config(name, source_code, &serde_json::json!({}), None)
            .await
    }

    /// Compile Rust source to WASM with config
    /// If source_code contains Handlebars syntax, it will be rendered with config first
    pub async fn compile_to_wasm_with_config(
        &self,
        name: &str,
        source_code: &str,
        config: &serde_json::Value,
        dependencies: Option<&serde_json::Value>,
    ) -> Result<CompilationResult> {
        eprintln!("🔨 Starting compilation for: {}", name);

        // 0. Render template if it contains Handlebars syntax
        let rendered_code = self
            .render_template(source_code, config)
            .context("Template rendering failed")?;

        // 1. Create temporary workspace
        let job_id = Uuid::new_v4();
        let (workspace, package_name) = self
            .create_workspace(job_id, name, &rendered_code, dependencies)
            .await?;
        eprintln!("📁 Workspace created at: {}", workspace.display());

        // 2. Run cargo component build with timeout (30 seconds)
        // SECURITY: Using cargo-component ensures proper Component Model WASM with validated adapters
        // PERFORMANCE: Direct component compilation, no conversion step needed
        // TARGET: wasm32-wasip2 enables wasi:sockets/tcp (std::net::TcpStream) and is the
        //         recommended Component Model target as of cargo-component 0.14+.
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            Command::new("cargo")
                .args(&[
                    "component",
                    "build",
                    "--release",
                    "--target",
                    "wasm32-wasip2",
                    "--manifest-path",
                    workspace
                        .join("Cargo.toml")
                        .to_str()
                        .unwrap_or("Cargo.toml"),
                ])
                .output(),
        )
        .await
        .context("Compilation timed out after 30 seconds")??;

        // 3. Check for errors
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);

            // Log compilation errors for debugging
            eprintln!("❌ Compilation failed for {}", name);
            eprintln!("STDOUT: {}", stdout);
            eprintln!("STDERR: {}", stderr);

            let errors = self.parse_errors(&stderr);

            // Clean up workspace
            tokio::fs::remove_dir_all(&workspace).await.ok();

            return Ok(CompilationResult {
                success: false,
                wasm_bytes: None,
                errors,
                size_bytes: 0,
                content_hash: String::new(),
                capability_world: CapabilityWorld::Unknown,
                imported_interfaces: vec![],
            });
        }

        // 4. Read Component WASM bytes
        // cargo-component produces Component Model WASM in target/wasm32-wasip2/release/
        // Package name uses underscores in the output filename
        let wasm_filename = format!("{}.wasm", package_name.replace("-", "_"));
        let wasm_path = workspace
            .join("target/wasm32-wasip2/release")
            .join(&wasm_filename);

        // 3.5. Run Wizer to snapshot the initialized memory
        let wizer_output_path =
            workspace.join(format!("{}_wizer.wasm", package_name.replace("-", "_")));
        let wizer_output = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            Command::new("wizer")
                .args(&[
                    "--allow-wasi",
                    "--wasm-bulk-memory=true",
                    "--wasm-multi-memory=true",
                    "--wasm-multi-value=true",
                    "--wasm-simd=true",
                    "--wasm-reference-types=true",
                    "-o",
                    wizer_output_path.to_str().unwrap_or("out.wasm"),
                    wasm_path.to_str().unwrap_or("in.wasm"),
                ])
                .output(),
        )
        .await;

        let final_wasm_path = match wizer_output {
            Ok(Ok(output)) if output.status.success() => wizer_output_path,
            Ok(Ok(output)) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::warn!(
                    "Wizer snapshot failed, falling back to uninitialized WASM: {}",
                    stderr
                );
                wasm_path
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    "Failed to execute wizer, falling back to uninitialized WASM: {}",
                    e
                );
                wasm_path
            }
            Err(_) => {
                tracing::warn!("Wizer snapshot timed out, falling back to uninitialized WASM");
                wasm_path
            }
        };

        let wasm_bytes = tokio::fs::read(&final_wasm_path)
            .await
            .context("Failed to read compiled WASM")?;

        // 5. Validate WASM structure
        self.validate_wasm(&wasm_bytes)?;

        // 6. Validate size (max 1MB)
        if wasm_bytes.len() > 1_048_576 {
            tokio::fs::remove_dir_all(&workspace).await.ok();
            bail!("Compiled WASM exceeds 1MB size limit");
        }

        // SECURITY: Check minimum size - valid WASM modules are at least a few KB
        if wasm_bytes.len() < 1024 {
            tokio::fs::remove_dir_all(&workspace).await.ok();
            bail!(
                "Compiled WASM is suspiciously small ({} bytes), likely compilation error",
                wasm_bytes.len()
            );
        }

        // 7. Compute hash for deduplication
        let mut hasher = Sha256::new();
        hasher.update(&wasm_bytes);
        let content_hash = hex::encode(hasher.finalize().as_slice());

        // 8. Inspect capability world — determines which WIT interfaces are imported.
        let inspection = worker::inspect_component(&wasm_bytes);
        tracing::info!(
            capability_world = %inspection.capability_world,
            interfaces = %inspection.imported_interfaces.join(", "),
            "Capability world detected"
        );

        // 9. Clean up workspace
        tokio::fs::remove_dir_all(&workspace).await.ok();

        eprintln!(
            "Compilation successful for {}. Size: {} bytes, Hash: {}",
            name,
            wasm_bytes.len(),
            content_hash
        );

        Ok(CompilationResult {
            success: true,
            wasm_bytes: Some(wasm_bytes.clone()),
            errors: vec![],
            size_bytes: wasm_bytes.len() as i32,
            content_hash,
            capability_world: inspection.capability_world,
            imported_interfaces: inspection.imported_interfaces,
        })
    }

    async fn create_workspace(
        &self,
        job_id: Uuid,
        name: &str,
        source_code: &str,
        dependencies: Option<&serde_json::Value>,
    ) -> Result<(PathBuf, String)> {
        let workspace = self.workspace_root.join(job_id.to_string());
        tokio::fs::create_dir_all(&workspace).await?;

        // Sanitize name for Cargo package (replace spaces and invalid chars)
        // Use hyphens (kebab-case) as required by cargo-component
        let package_name = name
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '-' })
            .collect::<String>()
            .to_lowercase();

        // Extract the WIT world from the source so the Cargo.toml target world matches
        // exactly what wit_bindgen::generate! declared. This prevents cargo-component
        // from guessing the world and guarantees the tiered-linker security model works.
        let world = extract_wit_world(source_code);

        let mut custom_deps = String::new();
        if let Some(serde_json::Value::Object(deps)) = dependencies {
            for (crate_name, version_val) in deps {
                if !crate_name
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                {
                    bail!("Invalid crate name: {}", crate_name);
                }

                let version = match version_val {
                    serde_json::Value::String(s) => s,
                    _ => bail!("Invalid dependency version format for crate {}", crate_name),
                };

                // Reject 'git' or 'path' anywhere in the version string to prevent LFI/RCE
                if version.contains("git")
                    || version.contains("path")
                    || version.contains('{')
                    || version.contains('}')
                {
                    bail!("Invalid dependency format for {}: only version strings allowed to prevent LFI", crate_name);
                }

                custom_deps.push_str(&format!("{} = \"{}\"\n", crate_name, version));
            }
        }

        // Write Cargo.toml configured for cargo-component
        // SECURITY: Component model provides better isolation than core WASM
        // PERFORMANCE: Optimized release builds with LTO
        let cargo_toml = format!(
            r#"[package]
name = "{}"
version = "0.1.0"
edition = "2021"

[dependencies]
wit-bindgen = "0.26.0"
serde = {{ version = "1.0", features = ["derive"] }}
serde_json = "1.0"
talos_sdk_macros = {{ path = "/app/talos_sdk_macros" }}
{}
[lib]
crate-type = ["cdylib"]

[package.metadata.component]
package = "talos:{}"

[package.metadata.component.target]
path = "wit/talos.wit"
world = "{}"

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
strip = true
"#,
            package_name, custom_deps, package_name, world
        );

        tokio::fs::write(workspace.join("Cargo.toml"), cargo_toml).await?;

        // Write lib.rs
        tokio::fs::create_dir_all(workspace.join("src")).await?;
        tokio::fs::write(workspace.join("src/lib.rs"), source_code).await?;

        // Copy WIT file to the workspace root's wit directory so the macro finds it at "../wit/talos.wit"
        tokio::fs::create_dir_all(self.workspace_root.join("wit")).await?;
        tokio::fs::copy(&self.wit_path, self.workspace_root.join("wit/talos.wit"))
            .await
            .context("Failed to copy WIT file")?;

        // Also copy it inside the package directory for cargo-component's Cargo.toml metadata
        tokio::fs::create_dir_all(workspace.join("wit")).await?;
        tokio::fs::copy(&self.wit_path, workspace.join("wit/talos.wit"))
            .await
            .context("Failed to copy WIT file")?;

        Ok((workspace, package_name))
    }

    fn parse_errors(&self, stderr: &str) -> Vec<CompilationError> {
        let mut errors = Vec::new();

        // Simple error parsing - look for "error:" lines
        for line in stderr.lines() {
            if line.contains("error:") || line.contains("error[E") {
                // Extract error message
                let message = line.trim().to_string();

                errors.push(CompilationError {
                    line: None,
                    column: None,
                    end_line: None,
                    end_column: None,
                    message,
                    severity: "error".to_string(),
                });
            }
        }

        // If no structured errors found, return the whole stderr
        if errors.is_empty() && !stderr.is_empty() {
            errors.push(CompilationError {
                line: None,
                column: None,
                end_line: None,
                end_column: None,
                message: stderr.to_string(),
                severity: "error".to_string(),
            });
        }

        errors
    }
}

/// Extract the WIT world name declared in a `wit_bindgen::generate!` call.
///
/// Scans the source for `world: "..."` and returns the quoted value. If the
/// pattern is not found, returns `"automation-node"` so existing modules that
/// pre-date the multi-world system continue to compile correctly.
fn extract_wit_world(source: &str) -> &str {
    // Check for standard wit_bindgen::generate! syntax
    const MARKER1: &str = r#"world: ""#;
    if let Some(start) = source.find(MARKER1) {
        let rest = &source[start + MARKER1.len()..];
        if let Some(end) = rest.find('"') {
            return &rest[..end];
        }
    }

    // Check for talos_node macro syntax (e.g. #[talos_node(world = "network-node")])
    const MARKER2: &str = r#"world = ""#;
    if let Some(start) = source.find(MARKER2) {
        let rest = &source[start + MARKER2.len()..];
        if let Some(end) = rest.find('"') {
            return &rest[..end];
        }
    }

    "automation-node"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationResult {
    pub success: bool,
    pub wasm_bytes: Option<Vec<u8>>,
    pub errors: Vec<CompilationError>,
    pub size_bytes: i32,
    pub content_hash: String,
    /// WIT capability world detected by binary inspection after compilation.
    pub capability_world: CapabilityWorld,
    /// The talos:core/* interfaces imported by the compiled component.
    pub imported_interfaces: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationError {
    pub line: Option<i32>,
    pub column: Option<i32>,
    pub end_line: Option<i32>,
    pub end_column: Option<i32>,
    pub message: String,
    pub severity: String,
}
