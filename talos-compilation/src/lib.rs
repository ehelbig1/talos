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
pub mod container;
pub mod dependency_allowlist;
pub mod js_templates;
pub mod scaffold;

// Re-export the allowlist gate at the crate root so callers (and the
// `mcp::utils` re-export shim in controller) can keep importing
// `validate_dependencies` from a stable location.
pub use dependency_allowlist::{get_allowed_dependencies, validate_dependencies};
use std::path::PathBuf;
use std::sync::OnceLock;
use talos_capability_world::CapabilityWorld;
use tokio::process::Command;
use tokio::sync::Semaphore;
use uuid::Uuid;

/// wasm-security-review (2026-05-22): default cap on the size of
/// user-supplied Rust source accepted by the compilation pipeline.
/// 1 MiB is comfortably above any realistic module (current
/// production modules sit well under 100 KiB) while still bounding a
/// hostile submission from holding a compilation slot for the full
/// 60-second cargo timeout. Override with `WASM_MAX_SOURCE_BYTES`.
pub(crate) const DEFAULT_MAX_SOURCE_BYTES: usize = 1_048_576;

/// wasm-security-review (2026-05-22): parse an env var as a positive
/// integer, falling back to `default` on missing / unparseable / zero
/// values. Mirrors `worker::runtime::nonzero_env_or_default` so the
/// "0 = misconfig, use default" semantic stays consistent across
/// crates without needing to depend on the worker crate from here.
pub(crate) fn nonzero_env_or_default(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

/// L-15 (2026-05-22): the RustSec advisory database is baked into the
/// builder image at `/opt/talos-advisory-db` at image-build time. The
/// runtime passes `--no-fetch` to cargo audit, so the DB is never
/// refreshed in-cluster — every compilation in a given image relies
/// on the advisory set that existed when the image was built. Without
/// a freshness check, a long-running cluster pinned to an old image
/// can silently miss new advisories for weeks or months.
///
/// This check uses the directory mtime as a proxy for the snapshot
/// date — the publish-images pipeline writes the DB then doesn't
/// touch it, so mtime corresponds to the bake-in moment. A more
/// precise signal would be the git HEAD commit date inside the
/// advisory-db repo, but mtime is portable (works for non-git
/// snapshots too) and good-enough for a coarse "is it stale" gate.
///
/// Thresholds:
/// - **Warn**: 30 days. Operators rebuild the builder image roughly
///   monthly per CLAUDE.md guidance; a warning log here surfaces the
///   condition in dashboards before it becomes a fail-closed.
/// - **Fail-closed in production**: 90 days. Three months without an
///   advisory refresh is too long; in production the compilation
///   refuses rather than rubber-stamping the build with stale data.
///   Outside production (dev/CI) the warning is enough.
///
/// `TALOS_ADVISORY_DB_MAX_AGE_DAYS` overrides the fail-closed
/// threshold (must be a positive integer). Use this for operators
/// who genuinely cannot rebuild monthly (air-gapped environments)
/// and have a compensating control elsewhere.
pub(crate) fn check_advisory_db_age(
    db_path: &str,
) -> Result<()> {
    use std::time::SystemTime;
    let meta = match std::fs::metadata(db_path) {
        Ok(m) => m,
        Err(e) => {
            // Missing DB is a separate failure mode the audit tool itself
            // surfaces with its own actionable error message. Don't
            // double-report here; just log and let the cargo audit
            // invocation produce the operator-recognised error.
            tracing::warn!(
                target: "talos_compilation",
                event_kind = "advisory_db_metadata_unreadable",
                path = %db_path,
                error = %e,
                "Could not stat the advisory DB to check freshness — \
                 cargo audit will surface the missing-DB error if applicable."
            );
            return Ok(());
        }
    };
    let dir_mtime = match meta.modified() {
        Ok(t) => t,
        Err(_) => return Ok(()),
    };

    // wasm-security-review (2026-05-22): the directory mtime alone is
    // a fragile proxy — a `touch` or filesystem-repair tool can
    // refresh it without any content change. Take the MAX of three
    // signals so each one can independently bound staleness:
    //   1. Directory mtime (legacy signal).
    //   2. `.git/refs/heads/main` (or master) mtime — the git ref
    //      file is written on every `git pull`/`git fetch`, so it
    //      captures the actual upstream-sync moment for a cloned
    //      advisory-db.
    //   3. Newest file mtime under `<db_path>/crates/` — captures the
    //      newest advisory added in any form (snapshot tarball,
    //      manual copy, etc.) even when no `.git` directory exists.
    // The freshest signal wins; if any signal returns "recent", the
    // gate doesn't trip even if another signal is stale.
    let mut freshest = dir_mtime;
    for ref_name in ["main", "master"] {
        let ref_path = format!("{db_path}/.git/refs/heads/{ref_name}");
        if let Ok(meta) = std::fs::metadata(&ref_path) {
            if let Ok(t) = meta.modified() {
                if t > freshest {
                    freshest = t;
                }
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(format!("{db_path}/crates")) {
        // Bound the walk: visit the per-crate dirs at depth-1 (taking
        // each dir's mtime). Going deeper would touch tens of
        // thousands of advisory files for marginal benefit — a
        // per-crate dir's mtime updates whenever any of its
        // advisories is added/modified.
        for entry in rd.flatten().take(20_000) {
            if let Ok(meta) = entry.metadata() {
                if let Ok(t) = meta.modified() {
                    if t > freshest {
                        freshest = t;
                    }
                }
            }
        }
    }

    let age = match SystemTime::now().duration_since(freshest) {
        Ok(d) => d,
        Err(_) => return Ok(()),
    };
    let age_days = age.as_secs() / 86_400;

    let fail_threshold_days: u64 = std::env::var("TALOS_ADVISORY_DB_MAX_AGE_DAYS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(90);

    let warn_threshold_days: u64 = 30;

    if age_days >= fail_threshold_days {
        if talos_config::is_production() {
            // Fail closed — production must not compile against a stale
            // advisory set. Operator action: rebuild the builder image.
            return Err(anyhow::anyhow!(
                "RustSec advisory database at {db_path} is {age_days} days old \
                 (max {fail_threshold_days} days in production). Rebuild the \
                 talos-builder image (`scripts/build-compiler-image.sh`) to \
                 refresh the baked-in advisory snapshot, or set \
                 TALOS_ADVISORY_DB_MAX_AGE_DAYS=<bigger_number> if you have a \
                 compensating control for stale advisories."
            ));
        }
        // Outside production: loud warning, don't block.
        tracing::warn!(
            target: "talos_compilation",
            event_kind = "advisory_db_stale_dev",
            path = %db_path,
            age_days,
            fail_threshold_days,
            "Advisory DB is past the production fail threshold but \
             this is dev/test — compilation continues. Rebuild the \
             builder image to refresh."
        );
    } else if age_days >= warn_threshold_days {
        tracing::warn!(
            target: "talos_compilation",
            event_kind = "advisory_db_aging",
            path = %db_path,
            age_days,
            warn_threshold_days,
            fail_threshold_days,
            "Advisory DB is aging — rebuild the talos-builder image \
             monthly to absorb new RustSec advisories."
        );
    }
    Ok(())
}

/// L-16: numeric helper used by the compile-provenance log line. Same
/// inputs as `check_advisory_db_age` but returns the age directly
/// rather than emit a verdict.
///
/// wasm-security-review (2026-05-22): mirrors the multi-signal logic
/// in `check_advisory_db_age` so the provenance log reports the same
/// freshness number the gate consults.
pub(crate) fn advisory_db_age_days(db_path: &str) -> Option<u64> {
    use std::time::SystemTime;
    let meta = std::fs::metadata(db_path).ok()?;
    let mut freshest = meta.modified().ok()?;
    for ref_name in ["main", "master"] {
        let ref_path = format!("{db_path}/.git/refs/heads/{ref_name}");
        if let Ok(meta) = std::fs::metadata(&ref_path) {
            if let Ok(t) = meta.modified() {
                if t > freshest {
                    freshest = t;
                }
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(format!("{db_path}/crates")) {
        for entry in rd.flatten().take(20_000) {
            if let Ok(meta) = entry.metadata() {
                if let Ok(t) = meta.modified() {
                    if t > freshest {
                        freshest = t;
                    }
                }
            }
        }
    }
    let age = SystemTime::now().duration_since(freshest).ok()?;
    Some(age.as_secs() / 86_400)
}

/// L-16: stable fingerprint of the effective dependency allowlist
/// (default set + extras-from-env). A SHA-256 of the sorted, joined
/// crate names — same input on two pods produces the same fingerprint,
/// and an operator changing
/// `MCP_ALLOWED_CRATE_DEPENDENCIES_EXTRA` flips the fingerprint
/// noticeably. We return the first 16 hex chars (8 bytes); collision
/// risk between distinct allowlists at that prefix length is ~2^-32
/// (birthday-bound) — fine for log-correlation, not load-bearing for
/// security.
pub(crate) fn dependency_allowlist_fingerprint() -> String {
    let names = dependency_allowlist::get_allowed_dependencies();
    // `get_allowed_dependencies` returns a HashSet (or similar
    // unordered set). Collect into a Vec and sort for stable input.
    let mut sorted: Vec<String> = names.into_iter().collect();
    sorted.sort();
    let joined = sorted.join(",");
    let digest = Sha256::digest(joined.as_bytes());
    hex::encode(&digest[..8])
}

/// L-16: fingerprint of the WIT host contract baked into the
/// `module-templates/wit/talos.wit` file the scaffold copies into
/// every compilation workspace. Computed once at process startup
/// (the file doesn't change between compiles in a given pod) and
/// cached in a [`OnceLock`].
pub(crate) fn wit_schema_fingerprint() -> &'static str {
    static FP: OnceLock<String> = OnceLock::new();
    FP.get_or_init(|| {
        // Search the same paths the scaffold uses, in priority order.
        let candidate_paths = [
            std::env::var("TALOS_WIT_PATH").ok(),
            Some("/app/module-templates/wit/talos.wit".to_string()),
            Some("module-templates/wit/talos.wit".to_string()),
            Some("wit/talos.wit".to_string()),
        ];
        for candidate in candidate_paths.into_iter().flatten() {
            if let Ok(bytes) = std::fs::read(&candidate) {
                let digest = Sha256::digest(&bytes);
                return hex::encode(&digest[..8]);
            }
        }
        "unknown".to_string()
    })
}

#[cfg(test)]
mod provenance_fingerprint_tests {
    use super::{dependency_allowlist_fingerprint, wit_schema_fingerprint};

    #[test]
    fn allowlist_fingerprint_is_stable_for_default_set() {
        // Two calls with the same env produce the same output.
        let a = dependency_allowlist_fingerprint();
        let b = dependency_allowlist_fingerprint();
        assert_eq!(a, b);
        // Format: 16 hex chars (8 bytes).
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn wit_schema_fingerprint_returns_hex_or_unknown() {
        let fp = wit_schema_fingerprint();
        // Either a 16-char hex digest, or the literal "unknown" if
        // the test env doesn't have the WIT file on disk (unit-test
        // sandbox typically doesn't).
        assert!(fp == "unknown" || (fp.len() == 16 && fp.chars().all(|c| c.is_ascii_hexdigit())));
    }
}

#[cfg(test)]
mod advisory_db_age_tests {
    use super::check_advisory_db_age;
    use std::time::Duration;

    /// A non-existent DB path is treated as "not our problem here" —
    /// cargo audit surfaces the missing-DB error. The freshness check
    /// must not double-fault.
    #[test]
    fn nonexistent_db_returns_ok() {
        let path = "/does/not/exist/advisory-db";
        let result = check_advisory_db_age(path);
        assert!(result.is_ok(), "missing DB should not error here");
    }

    #[test]
    fn fresh_db_passes() {
        // A tempdir created now has mtime = now → age = 0 days.
        let tmp = tempfile::tempdir().expect("create tempdir");
        let p = tmp.path().to_str().unwrap();
        check_advisory_db_age(p).expect("fresh dir should pass");
    }

    /// 100-day-old DB in dev environment: warns but doesn't fail.
    /// We can't easily backdate mtime in a portable way for the
    /// production-fail-closed branch test without touching the
    /// filesystem; the env-var-tunable threshold is exercised
    /// indirectly via the override path.
    #[test]
    fn old_db_with_huge_threshold_passes() {
        // Even a hypothetically 1000-day-old DB passes if the
        // operator opts out via the env-var override.
        let tmp = tempfile::tempdir().expect("create tempdir");
        let p = tmp.path().to_str().unwrap();
        std::env::set_var("TALOS_ADVISORY_DB_MAX_AGE_DAYS", "100000");
        let result = check_advisory_db_age(p);
        std::env::remove_var("TALOS_ADVISORY_DB_MAX_AGE_DAYS");
        assert!(
            result.is_ok(),
            "operator-tunable threshold should override default — got {result:?}"
        );
    }
}

/// M-13: gate for the host-process JS/Python compile paths.
///
/// `compile_js_to_wasm` runs `jco componentize` on the host; `compile_python_to_wasm`
/// runs `componentize-py` on the host. Both invoke their respective
/// language toolchains in-process — `componentize-py` in particular runs
/// arbitrary Python introspection at compile time, which is a trivial
/// RCE escalation if the source is operator-untrusted. Until the
/// containerised JS/Python toolchain image lands (matching the Rust
/// `container::build_command` pattern) we fail closed in production
/// unless the operator explicitly opts back in.
///
/// `TALOS_COMPILATION_ALLOW_HOST_FALLBACK=true` re-enables the host
/// path — same gate as the Rust host-fallback escape hatch in
/// `container::host_fallback_allowed`. A single deployment-wide
/// switch keeps the security model consistent across languages.
///
/// Outside production (dev / test) the gate is a no-op so local
/// `cargo test` runs pass without env setup.
fn require_host_lang_toolchain_allowed(language: &str) -> Result<()> {
    if !talos_config::is_production() {
        return Ok(());
    }
    let allowed = matches!(
        std::env::var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK")
            .ok()
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("true" | "1" | "yes")
    );
    if allowed {
        tracing::warn!(
            language,
            "compile_to_wasm({language}): host toolchain enabled via TALOS_COMPILATION_ALLOW_HOST_FALLBACK — \
             multi-tenant deployments MUST containerise the {language} toolchain instead. \
             See docs/platform-primitive-checklist.md (M-13)."
        );
        return Ok(());
    }
    bail!(
        "{language} compilation is disabled in production: the {language} toolchain currently runs \
         on the host (no sandbox) which is unsafe for multi-tenant deployments. \
         Single-tenant operators can opt in by setting TALOS_COMPILATION_ALLOW_HOST_FALLBACK=true; \
         multi-tenant deploys should wait for the containerised {language} build image."
    );
}

/// Concurrency guard for `cargo component build` processes.
/// Limits the number of concurrent compilations to prevent resource exhaustion.
/// Defaults to the number of CPU cores, configurable via `TALOS_MAX_COMPILATIONS`.
///
/// MCP-638 (2026-05-13): clamp the configured value to ≥ 1. Pre-fix
/// `TALOS_MAX_COMPILATIONS=0` parsed to `usize 0` and `Semaphore::new(0)`
/// never admits an `acquire().await` — every compile attempt blocks
/// forever and operators see compile jobs accumulate with no log
/// signal pointing at the misconfiguration. Sibling to the same fix
/// in `talos-execution-orchestration::trigger::exec_semaphore`.
fn compilation_semaphore() -> &'static Semaphore {
    static SEMAPHORE: OnceLock<Semaphore> = OnceLock::new();
    SEMAPHORE.get_or_init(|| {
        let raw = std::env::var("TALOS_MAX_COMPILATIONS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(3); // Default to 3 concurrent compilations
        let max = if raw == 0 {
            tracing::warn!(
                target: "talos_compilation",
                event_kind = "compilation_semaphore_zero_clamped",
                configured = raw,
                clamped_to = 1,
                "TALOS_MAX_COMPILATIONS=0 would deadlock every compile \
                 (Semaphore::new(0) never admits). Clamping to 1 (serial \
                 compile). Set =1 explicitly to silence this warning."
            );
            1
        } else {
            raw
        };
        tracing::info!(
            max_compilations = max,
            "Compilation concurrency guard initialized"
        );
        Semaphore::new(max)
    })
}

pub struct CompilationService {
    workspace_root: PathBuf,
    wit_path: PathBuf,
    event_tx: talos_engine_events::CompilationEventSender,
}

impl CompilationService {
    pub fn new(
        workspace_root: PathBuf,
        event_tx: talos_engine_events::CompilationEventSender,
    ) -> Self {
        // Resolve the WIT fixture path with this priority:
        //   1. TALOS_WIT_PATH env var (operator override — lets Docker images
        //      place the file wherever makes sense for the runtime image layout).
        //   2. Compile-time relative path: $CARGO_MANIFEST_DIR/../wit/talos.wit
        //      which is correct for `cargo run` from the workspace root.
        let wit_path = std::env::var("TALOS_WIT_PATH")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new(".."))
                    .join("wit/talos.wit")
            });

        if !wit_path.exists() {
            tracing::error!(
                wit_path = %wit_path.display(),
                "WIT fixture missing at expected path"
            );
        }

        // Startup-time advisory for the host-language fallback flag.
        // The per-compile warning inside `require_host_lang_toolchain_allowed`
        // is operator-blind until someone actually attempts a JS/Python
        // compile — an attacker who knows the flag is set could fire
        // their malicious module on the FIRST compile attempt, before
        // any warning has surfaced. This boot-time log makes the
        // dangerous mode impossible to overlook in production.
        //
        // Fires once per process at construction, not per request,
        // so log volume is bounded.
        if talos_config::is_production()
            && matches!(
                std::env::var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK")
                    .ok()
                    .as_deref()
                    .map(str::trim)
                    .map(str::to_ascii_lowercase)
                    .as_deref(),
                Some("true" | "1" | "yes")
            )
        {
            tracing::warn!(
                target: "talos_compilation::startup_advisory",
                flag = "TALOS_COMPILATION_ALLOW_HOST_FALLBACK",
                "PRODUCTION DEPLOYMENT WITH HOST-LANGUAGE FALLBACK ENABLED. \
                 JavaScript and Python user-supplied source will be \
                 compiled by host-side toolchains WITHOUT container \
                 isolation. componentize-py executes arbitrary Python \
                 introspection at build time — effectively `exec(user_source)`. \
                 Single-tenant homelab use only. If this is a multi-tenant \
                 deployment, UNSET this variable immediately. \
                 See docs/platform-primitive-checklist.md (M-13)."
            );
        }

        Self {
            workspace_root,
            wit_path,
            event_tx,
        }
    }

    pub fn send_event(
        &self,
        user_id: Uuid,
        job_id: Uuid,
        status: &str,
        message: Option<String>,
        progress: Option<f32>,
    ) {
        let event = talos_engine_events::CompilationEvent {
            job_id,
            user_id,
            status: status.to_string(),
            message,
            progress,
        };
        let _ = self.event_tx.send(event);
    }

    /// Render template with config (if it contains Handlebars syntax)
    /// Security: Uses strict Handlebars mode with HTML escaping enabled
    fn render_template(&self, template: &str, config: &serde_json::Value) -> Result<String> {
        // Only render through Handlebars if the template explicitly opts in
        // with a `// handlebars: true` directive line.
        let has_handlebars = template
            .lines()
            .any(|line| line.trim() == "// handlebars: true");
        if !has_handlebars {
            return Ok(template.to_string());
        }

        // wasm-security-review (2026-05-22): refuse templates that
        // substitute the WIT world string from a Handlebars variable.
        // A template like `#[talos_node(world = "{{user_world}}")]`
        // would let config control the capability world declared in
        // source. Defense-in-depth: the post-compile detected-vs-
        // declared check would catch a binary that imports more than
        // its declared world, but that check is fail-CLOSED on
        // observed escalation rather than on intent — and the
        // declared world is the input to that very check. Forbidding
        // dynamic world strings at template-parse time eliminates the
        // class entirely.
        if let Some(token) = template_substitutes_world(template) {
            anyhow::bail!(
                "template-injection: the `world = ...` declaration must be a \
                 hard-coded literal, not a Handlebars substitution \
                 (found `{token}`). The WIT capability world drives the \
                 worker's tiered linker — letting config choose it would let \
                 an operator silently grant a module higher privileges than \
                 the source attribute declares. Hard-code the world, e.g. \
                 `#[talos_node(world = \"http-node\")]`."
            );
        }

        let mut handlebars = Handlebars::new();

        // SECURITY: Enable strict mode — missing template variables produce an error
        // rather than silently substituting an empty string.
        handlebars.set_strict_mode(true);

        // SECURITY: Disable HTML escaping for Rust code generation.
        // HTML escaping (&→&amp;, <→&lt;, etc.) would corrupt valid Rust syntax,
        // e.g. `a < b` → `a &lt; b`, breaking compilation. We rely instead on
        // validate_config_values() below, which rejects characters that could
        // break out of a string literal context in generated source code.
        handlebars.register_escape_fn(handlebars::no_escape);

        // Validate config before rendering — must run BEFORE substitution so checks
        // apply to the raw user-supplied values, not the post-render output.
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

        // For core WASM: bytes 4–7 are the 4-byte version field; u32-LE = 1.
        // For WASM components (Component Model): bytes 4–5 are the layer (0x0d, 0x00)
        // and bytes 6–7 are the version (0x01, 0x00). Reading all four as u32-LE gives
        // 0x00_01_00_0d = 65549. Accept any value up to 2^26 — wasmtime does full
        // structural validation at instantiation time.
        let version =
            u32::from_le_bytes([wasm_bytes[4], wasm_bytes[5], wasm_bytes[6], wasm_bytes[7]]);

        match version {
            1 => tracing::debug!("WASM validation passed: core WASM module (version 1)"),
            _ if version < 67_108_864 => {
                tracing::debug!(version, "WASM validation passed: component model binary")
            }
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

                // SECURITY: Restrict substitution values to printable ASCII.
                //
                // Config values are typically substituted into Rust string literals
                // (`const KEY: &str = "{{API_KEY}}";`). The strict allowlist below
                // catches the entire injection attack surface in one pass:
                //   * Control chars (`\n`, `\r`, `\0`, `\x1b` ESC, …) — break source structure.
                //   * ASCII `"` / `\\` — break out of string-literal context.
                //   * Unicode look-alikes for quote/backslash (e.g. U+201C "LEFT DOUBLE
                //     QUOTATION MARK") — visually misleading even if rustc treats only
                //     ASCII `"` as the string delimiter; rejecting them keeps the
                //     "no quote-like chars" invariant honest.
                //   * Any non-ASCII char — credential values (API keys, tokens,
                //     passwords) are ASCII by every existing format. Rejecting non-ASCII
                //     also closes a class of confusable / IDN / RTL-override attacks
                //     against operators reading the rendered source.
                //
                // Allowed range: U+0020 (SPACE) through U+007E (`~`) inclusive,
                // EXCLUDING `"` (U+0022) and `\` (U+005C).
                for (idx, ch) in s.char_indices() {
                    let code = ch as u32;
                    let is_printable_ascii = (0x20..=0x7e).contains(&code);
                    let is_quote_or_backslash = ch == '"' || ch == '\\';
                    if !is_printable_ascii || is_quote_or_backslash {
                        bail!(
                            "Config value contains a disallowed character at byte {} \
                             (U+{:04X}). Only printable ASCII (U+0020..=U+007E) is \
                             permitted in compile-time substitution values, and \
                             quote (U+0022) / backslash (U+005C) are excluded to \
                             prevent string-literal escape injection.",
                            idx, code
                        );
                    }
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
        user_id: Uuid,
        job_id: Uuid,
        name: &str,
        source_code: &str,
    ) -> Result<CompilationResult> {
        self.compile_to_wasm_with_config(
            user_id,
            job_id,
            name,
            source_code,
            &serde_json::json!({}),
            None,
        )
        .await
    }

    /// Compile Rust source to WASM with config
    /// If source_code contains Handlebars syntax, it will be rendered with config first
    pub async fn compile_to_wasm_with_config(
        &self,
        user_id: Uuid,
        job_id: Uuid,
        name: &str,
        source_code: &str,
        config: &serde_json::Value,
        dependencies: Option<&serde_json::Value>,
    ) -> Result<CompilationResult> {
        // wasm-security-review (2026-05-22): bound the source size
        // BEFORE acquiring a compilation slot or touching the filesystem.
        // A hostile 100 MiB source string would otherwise hold the
        // semaphore for the full 60-second cargo timeout while doing
        // nothing useful — and `cargo component build` would likely OOM
        // before producing an error. WASM_MAX_SOURCE_BYTES overrides the
        // default cap.
        let max_source_bytes = nonzero_env_or_default("WASM_MAX_SOURCE_BYTES", DEFAULT_MAX_SOURCE_BYTES);
        if source_code.len() > max_source_bytes {
            return Ok(CompilationResult {
                success: false,
                wasm_bytes: None,
                errors: vec![CompilationError {
                    line: None,
                    column: None,
                    end_line: None,
                    end_column: None,
                    message: format!(
                        "source-too-large: source code is {} bytes but the cap is {} bytes \
                         (set WASM_MAX_SOURCE_BYTES to raise it). Reduce the module size or \
                         split into multiple smaller modules.",
                        source_code.len(),
                        max_source_bytes
                    ),
                    severity: "error".to_string(),
                }],
                size_bytes: 0,
                content_hash: String::new(),
                capability_world: CapabilityWorld::Unknown,
                imported_interfaces: vec![],
            });
        }

        self.send_event(
            user_id,
            job_id,
            "starting",
            Some("Initializing compilation environment...".to_string()),
            Some(0.05),
        );

        // Acquire compilation permit with timeout (backpressure if at capacity)
        let _permit = tokio::time::timeout(
            std::time::Duration::from_secs(120), // 2 min wait for compilation slot
            compilation_semaphore().acquire(),
        )
        .await
        .map_err(|_| {
            let max = std::env::var("TALOS_MAX_COMPILATIONS")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(3);
            anyhow::anyhow!(
                "Compilation queue full (max {} concurrent). All slots busy for >2 minutes. Try again shortly.",
                max
            )
        })?
        .map_err(|_| anyhow::anyhow!("Compilation semaphore closed"))?;

        tracing::debug!(name, "starting compilation");
        let compile_start = std::time::Instant::now();

        // 0a. Run static source lints (instant, no compilation overhead).
        self.send_event(
            user_id,
            job_id,
            "linting",
            Some("Running static source analysis...".to_string()),
            Some(0.1),
        );
        let lint_warnings = analyze::lint_source_code(source_code);
        let lint_errors: Vec<CompilationError> = lint_warnings
            .iter()
            .filter(|e| e.severity == "error")
            .cloned()
            .collect();
        if !lint_errors.is_empty() {
            self.send_event(
                user_id,
                job_id,
                "failed",
                Some("Static analysis failed with errors".to_string()),
                Some(1.0),
            );
            return Ok(CompilationResult {
                success: false,
                wasm_bytes: None,
                errors: lint_errors,
                size_bytes: 0,
                content_hash: String::new(),
                capability_world: CapabilityWorld::Unknown,
                imported_interfaces: vec![],
            });
        }

        // 0. Render template if it contains Handlebars syntax
        self.send_event(
            user_id,
            job_id,
            "scaffolding",
            Some("Generating project source code...".to_string()),
            Some(0.15),
        );
        let rendered_code = self
            .render_template(source_code, config)
            .context("Template rendering failed")?;
        tracing::info!(
            elapsed_ms = compile_start.elapsed().as_millis() as u64,
            name,
            "Compilation phase: source generated"
        );

        // 1. Create temporary workspace
        let (workspace, package_name) = self
            .create_workspace(job_id, name, &rendered_code, dependencies)
            .await?;
        tracing::info!(elapsed_ms = compile_start.elapsed().as_millis() as u64, name, job_id = %job_id, "Compilation phase: workspace created");

        // Compute the source-declared WIT world here so we can compare
        // it against the binary-inspected world post-compile. A mismatch
        // means the macro expansion targeted a different world than the
        // raw-source declaration suggested — either a bait-and-switch
        // attempt or, more likely, a typo/comment-confusion bug. The
        // worker's tiered linker will reject the binary at instantiation
        // (defense-in-depth holds) but flagging the mismatch at compile
        // time gives operators a clearer failure mode than "module fails
        // to load on every dispatch".
        let declared_world = extract_wit_world(&rendered_code);

        // L-37: run the rest of compilation in an inner method so the
        // single workspace-cleanup site below covers EVERY exit path
        // (success, audit-fail, build-fail, validation-fail, panic). The
        // pre-refactor code had 9 inline `remove_dir_all` calls scattered
        // across early-return arms; a panic between any two of those
        // leaked the workspace.
        let result = self
            .compile_with_workspace(
                user_id,
                job_id,
                name,
                &workspace,
                &package_name,
                lint_warnings,
                compile_start,
                &declared_world,
            )
            .await;

        // Cleanup workspace on ALL paths (success, error, panic-recovery
        // boundary). Mirrors `compile_python_module`'s pattern.
        tokio::fs::remove_dir_all(&workspace).await.ok();

        result
    }

    /// Inner compilation kernel — assumes the workspace already exists
    /// at `workspace`. The caller is responsible for cleanup so this
    /// function can use `?` and early returns freely without leaking
    /// the workspace dir.
    #[allow(clippy::too_many_arguments)]
    async fn compile_with_workspace(
        &self,
        user_id: Uuid,
        job_id: Uuid,
        name: &str,
        workspace: &PathBuf,
        package_name: &str,
        lint_warnings: Vec<CompilationError>,
        compile_start: std::time::Instant,
        // Source-declared capability world (from `extract_wit_world`).
        // Compared against the binary-inspected world after compilation
        // to detect declared/actual mismatches (see step 8).
        declared_world: &str,
    ) -> Result<CompilationResult> {
        // 1.4. Pre-generate `Cargo.lock` so `cargo audit --no-fetch`
        // (which runs inside `--network=none`) has a real lockfile to
        // scan. `create_workspace` writes Cargo.toml + src/lib.rs but
        // never produces a lockfile — the build step (1.6) is what
        // historically generated it as a side-effect, but audit ran
        // BEFORE that. Without a lockfile cargo-audit exits non-zero
        // with no JSON output; production fails closed but dev
        // silently warned through (N-7 from the talos-compilation
        // review — dev fail-open).
        //
        // Wasm-security review 2026-05-23 (H-6): lockfile generation
        // now runs INSIDE the same `--network=none --read-only` build
        // container as the compile + audit steps. Pre-fix it ran
        // directly on the controller host (where vault tokens, master
        // DEK, and LLM keys are mounted) — the doc-comment justified
        // this with "cargo generate-lockfile only does dependency
        // resolution," which is true today but doesn't make it safe to
        // run user-controlled `Cargo.toml` parsing on the controller
        // host. If a future cargo TOML-parsing or resolver CVE lands,
        // an attacker would land code execution on the credential-
        // bearing host. The fix mirrors the audit-command pattern:
        // build the sandboxed Command via `container::build_command`,
        // then append the `generate-lockfile --offline --quiet` args.
        // `--offline` still forces local-registry resolution, so the
        // `--network=none` container doesn't break legitimate use.
        //
        // We compute `cargo_registry_cache` and `wit_dir` here (used
        // by `container::build_command` to mount the registry cache
        // RO and the WIT directory RO into the container). They were
        // previously declared after this block; pull them up.
        let cargo_registry_cache = dirs_next::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join(".cargo/registry");
        let wit_dir = self
            .wit_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let lockfile_cmd = container::build_command(workspace, &cargo_registry_cache, wit_dir);
        let lockfile_result = match lockfile_cmd {
            Ok(mut cmd) => {
                tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    cmd.args(["generate-lockfile", "--offline", "--quiet"])
                        .current_dir(workspace)
                        .output(),
                )
                .await
            }
            Err(e) => {
                tracing::warn!(
                    target: "talos_compilation",
                    event_kind = "lockfile_container_unavailable",
                    error = %e,
                    "Container build_command unavailable for lockfile gen — \
                     falling back to direct cargo (same as audit_command's fallback policy)"
                );
                tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    Command::new("cargo")
                        .args(["generate-lockfile", "--offline", "--quiet"])
                        .current_dir(workspace)
                        .output(),
                )
                .await
            }
        };
        match &lockfile_result {
            Ok(Ok(out)) if out.status.success() => {
                tracing::debug!(
                    target: "talos_compilation",
                    event_kind = "lockfile_generated",
                    "Pre-audit Cargo.lock generated"
                );
            }
            Ok(Ok(out)) => {
                tracing::warn!(
                    target: "talos_compilation",
                    event_kind = "lockfile_generation_failed",
                    fallback_reason = "cargo_nonzero",
                    stderr = %String::from_utf8_lossy(&out.stderr),
                    "cargo generate-lockfile --offline returned non-zero — \
                     audit will run without a lockfile and likely surface as \
                     missing-lockfile (production fails closed, dev warns)"
                );
            }
            Err(_) | Ok(Err(_)) => {
                tracing::warn!(
                    target: "talos_compilation",
                    event_kind = "lockfile_generation_failed",
                    fallback_reason = "spawn_or_timeout",
                    "cargo generate-lockfile --offline timed out or failed to spawn — \
                     audit will run without a lockfile"
                );
            }
        }

        // 1.5. CVE scan
        self.send_event(
            user_id,
            job_id,
            "auditing",
            Some("Performing dependency security audit...".to_string()),
            Some(0.2),
        );
        // `cargo_registry_cache` was hoisted up above (H-6) for the
        // sandboxed lockfile-gen step; reuse it here.
        let audit_cmd = container::audit_command(workspace, &cargo_registry_cache);
        // Stable image-baked advisory DB path. Both controller/Dockerfile
        // and Dockerfile.builder stage the DB at /opt/talos-advisory-db
        // (chmod a+rX, world-readable). Passing --db explicitly avoids
        // depending on $CARGO_HOME, which the runtime sets to a tmpfs
        // path (/tmp/cargo-cache) that gets wiped per pod.
        let audit_db = container::ADVISORY_DB_PATH;
        // L-15: freshness check on the baked-in DB. Fails closed in
        // production at 90 days. Outside production (dev/CI) the
        // check warns but continues — see `check_advisory_db_age` for
        // the full policy. We run this BEFORE the audit so a stale
        // DB produces a clear actionable error instead of a confusing
        // "0 vulnerabilities found" pass against an obsolete snapshot.
        if let Err(e) = check_advisory_db_age(audit_db) {
            self.send_event(
                user_id,
                job_id,
                "failed",
                Some(format!("Advisory DB age check failed: {e}")),
                Some(1.0),
            );
            return Err(e);
        }
        let audit_args = ["audit", "--db", audit_db, "--json", "--no-fetch"];
        let audit_result = match audit_cmd {
            Ok(mut cmd) => {
                tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    cmd.args(audit_args).current_dir(&workspace).output(),
                )
                .await
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to build audit container command");
                // Fall back to direct cargo
                tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    Command::new("cargo")
                        .args(audit_args)
                        .current_dir(&workspace)
                        .output(),
                )
                .await
            }
        };

        match audit_result {
            Ok(Ok(ref out)) if !out.status.success() => {
                let summary = parse_audit_summary(&out.stdout);
                if summary.count > 0 {
                    self.send_event(
                        user_id,
                        job_id,
                        "failed",
                        Some(format!(
                            "Audit failed: {} vulnerabilities found",
                            summary.count
                        )),
                        Some(1.0),
                    );
                    // Confirmed vulnerabilities — block compilation.
                    // (cleanup handled by outer compile_to_wasm_with_config)
                    return Err(anyhow::anyhow!(
                        "Dependency security audit failed — {} vulnerable crate(s): {}. \
                         Remove or downgrade the affected dependency.",
                        summary.count,
                        summary.names.join(", "),
                    ));
                }
                if talos_config::is_production() {
                    self.send_event(
                        user_id,
                        job_id,
                        "failed",
                        Some("Audit tool failed in production".to_string()),
                        Some(1.0),
                    );
                    // (cleanup handled by outer compile_to_wasm_with_config)
                    return Err(anyhow::anyhow!(
                        "cargo-audit exited with an error in production. \
                         Most likely the RustSec advisory database is missing or stale inside the \
                         talos-builder image — rebuild it via `scripts/build-compiler-image.sh` \
                         (the Dockerfile pre-fetches the DB at build time; --no-fetch is enforced \
                         at runtime because the sandbox denies network)."
                    ));
                }
                tracing::warn!(
                    target: "talos_compilation",
                    event_kind = "audit_skipped_dev",
                    "cargo-audit exited non-zero with no parsed vulnerabilities — tool, \
                     advisory-DB, or missing-Cargo.lock issue. Skipping in dev mode (production \
                     would fail closed). If this fires repeatedly, check the lockfile_generated \
                     event from step 1.4 — a failed pre-audit `cargo generate-lockfile --offline` \
                     will reliably trip this branch."
                );
            }
            Err(_) | Ok(Err(_)) => {
                if talos_config::is_production() {
                    self.send_event(
                        user_id,
                        job_id,
                        "failed",
                        Some("Audit tool unavailable in production".to_string()),
                        Some(1.0),
                    );
                    // (cleanup handled by outer compile_to_wasm_with_config)
                    return Err(anyhow::anyhow!(
                        "cargo-audit unavailable or timed out — blocked in production. \
                         Verify the talos-builder image has cargo-audit installed AND a populated \
                         advisory-db at /home/builder/.cargo/advisory-db (rebuild via \
                         `scripts/build-compiler-image.sh` if missing)."
                    ));
                }
                tracing::warn!("cargo-audit not available or timed out — skipping CVE scan in non-production mode");
            }
            _ => {} // Clean audit (exit 0) — proceed
        }

        // 2. Run cargo component build with timeout (60 seconds)
        self.send_event(
            user_id,
            job_id,
            "building",
            Some("Compiling Rust source to WASM component...".to_string()),
            Some(0.3),
        );
        // `wit_dir` was hoisted up above (H-6) for the sandboxed
        // lockfile-gen step; reuse it here.
        let build_cmd = container::build_command(workspace, &cargo_registry_cache, wit_dir);
        let output = match build_cmd {
            Ok(mut cmd) => {
                tokio::time::timeout(
                    std::time::Duration::from_secs(60), // 60s for large worlds like automation-node
                    cmd.args(&[
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
                .context("Compilation timed out after 60 seconds")?
            }
            Err(e) => {
                self.send_event(
                    user_id,
                    job_id,
                    "failed",
                    Some(format!("Build setup failed: {}", e)),
                    Some(1.0),
                );
                tracing::error!(error = %e, "Failed to build compilation container command");
                // (cleanup handled by outer compile_to_wasm_with_config)
                return Err(e.context("Container compilation setup failed"));
            }
        }?;

        tracing::info!(
            elapsed_ms = compile_start.elapsed().as_millis() as u64,
            name,
            "Compilation phase: cargo build complete"
        );

        // 3. Check for errors
        if !output.status.success() {
            self.send_event(
                user_id,
                job_id,
                "failed",
                Some("Cargo build failed with compilation errors".to_string()),
                Some(1.0),
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);

            let workspace_prefix = workspace.to_str().unwrap_or("");
            let sanitized_stderr = if workspace_prefix.is_empty() {
                stderr.to_string()
            } else {
                stderr.replace(workspace_prefix, "<workspace>")
            };

            tracing::error!(name, stdout = %stdout, stderr = %sanitized_stderr, "compilation failed");

            let errors = self.parse_errors(&sanitized_stderr);

            // (cleanup handled by outer compile_to_wasm_with_config)
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

        self.send_event(
            user_id,
            job_id,
            "success",
            Some("Module successfully compiled and verified".to_string()),
            Some(1.0),
        );

        // 4. Locate and read the component WASM binary.
        //
        // cargo-component 0.21+ with --target wasm32-wasip2 writes the adapted
        // component model binary to ONE of two locations depending on its version
        // and internal behaviour:
        //   A) target/wasm32-wasip1/release/name.wasm  (older cargo-component behaviour)
        //   B) target/wasm32-wasip2/release/name.wasm  (newer behaviour, wasip2 is already
        //                                               a component target)
        //
        // A WASM component model binary starts with the 8-byte magic sequence:
        //   00 61 73 6d  0d 00 01 00
        // A core WASM module starts with:
        //   00 61 73 6d  01 00 00 00
        //
        // Strategy: try the path that cargo-component reported via its "Creating component"
        // stdout line first, then probe both candidate paths for the component magic and
        // use whichever one is valid.  This is robust across cargo-component versions and
        // across CARGO_TARGET_DIR environments.
        let wasm_filename = format!("{}.wasm", package_name.replace("-", "_"));
        let target_base = std::env::var("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| workspace.join("target"));

        // Parse "Creating component /path/to/name.wasm" from cargo stdout.
        // The path may be absolute or relative to the compilation workspace.
        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let component_path_from_stdout: Option<PathBuf> = stdout_str.lines().find_map(|line| {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("Creating component ") {
                let raw = PathBuf::from(rest.trim());
                // Prefer absolute path; fall back to resolving relative to workspace.
                if raw.is_absolute() && raw.exists() {
                    Some(raw)
                } else {
                    let resolved = workspace.join(&raw);
                    if resolved.exists() {
                        Some(resolved)
                    } else {
                        None
                    }
                }
            } else {
                None
            }
        });

        // Helper: true if the file has the WASM component model magic (0x0d at byte 4).
        // Core WASM has 0x01 at byte 4; component model binaries have 0x0d.
        // Reads only the first 8 bytes so this is O(1) regardless of file size.
        fn is_component_magic(p: &PathBuf) -> bool {
            use std::io::Read;
            let Ok(mut f) = std::fs::File::open(p) else {
                return false;
            };
            let mut buf = [0u8; 8];
            matches!(
                f.read(&mut buf),
                Ok(n) if n >= 8 && &buf[0..4] == b"\0asm" && buf[4] == 0x0d
            )
        }

        // Return the modification time of a file, or None if unavailable.
        fn mtime(p: &PathBuf) -> Option<std::time::SystemTime> {
            std::fs::metadata(p).and_then(|m| m.modified()).ok()
        }

        let candidate_wasip1 = target_base
            .join("wasm32-wasip1/release")
            .join(&wasm_filename);
        let candidate_wasip2 = target_base
            .join("wasm32-wasip2/release")
            .join(&wasm_filename);

        let final_wasm_path: PathBuf = if let Some(p) = component_path_from_stdout {
            // cargo-component told us exactly where the component landed.
            tracing::info!(path = %p.display(), "cargo-component reported component path via stdout");
            p
        } else {
            // Fallback: inspect both candidate paths.
            // After a successful compilation the FRESHEST file with component-model magic
            // is the one just written.  A stale binary from a previous session will have
            // an older mtime even if it also happens to be a component model binary.
            let wasip1_ok = is_component_magic(&candidate_wasip1);
            let wasip2_ok = is_component_magic(&candidate_wasip2);
            let wasip1_mtime = mtime(&candidate_wasip1);
            let wasip2_mtime = mtime(&candidate_wasip2);

            tracing::info!(
                wasip1_is_component = wasip1_ok,
                wasip2_is_component = wasip2_ok,
                wasip1_mtime = ?wasip1_mtime,
                wasip2_mtime = ?wasip2_mtime,
                cargo_stdout = %stdout_str.trim(),
                "cargo-component stdout parse missed 'Creating component'; probing candidate paths"
            );

            match (wasip1_ok, wasip2_ok) {
                (true, true) => {
                    // Both are component binaries; use the one most recently written.
                    if wasip2_mtime >= wasip1_mtime {
                        tracing::info!(path = %candidate_wasip2.display(), "selecting wasm32-wasip2 (fresher)");
                        candidate_wasip2
                    } else {
                        tracing::info!(path = %candidate_wasip1.display(), "selecting wasm32-wasip1 (fresher)");
                        candidate_wasip1
                    }
                }
                (true, false) => {
                    tracing::info!(path = %candidate_wasip1.display(), "selecting wasm32-wasip1 (only valid component)");
                    candidate_wasip1
                }
                (false, true) => {
                    tracing::info!(path = %candidate_wasip2.display(), "selecting wasm32-wasip2 (only valid component)");
                    candidate_wasip2
                }
                (false, false) => {
                    tracing::error!(
                        wasip1_exists = candidate_wasip1.exists(),
                        wasip2_exists = candidate_wasip2.exists(),
                        cargo_stdout = %stdout_str,
                        "WASM component binary not found at either candidate path"
                    );
                    anyhow::bail!(
                        "cargo-component succeeded but no component binary was found.\n\
                         Checked:\n  {} (component={wasip1_ok})\n  {} (component={wasip2_ok})\n\
                         CARGO_TARGET_DIR={:?}",
                        candidate_wasip1.display(),
                        candidate_wasip2.display(),
                        std::env::var("CARGO_TARGET_DIR").ok()
                    )
                }
            }
        };

        let wasm_bytes = tokio::fs::read(&final_wasm_path).await.with_context(|| {
            format!(
                "Failed to read compiled WASM from {}",
                final_wasm_path.display()
            )
        })?;
        tracing::info!(
            elapsed_ms = compile_start.elapsed().as_millis() as u64,
            name,
            size_bytes = wasm_bytes.len(),
            "Compilation phase: WASM extracted"
        );

        // 5. Validate WASM structure
        // (cleanup handled by outer compile_to_wasm_with_config)
        self.validate_wasm(&wasm_bytes)?;

        // 6. Validate size (max 1MB)
        if wasm_bytes.len() > 1_048_576 {
            bail!("Compiled WASM exceeds 1MB size limit");
        }

        // SECURITY: Check minimum size - valid WASM modules are at least a few KB
        if wasm_bytes.len() < 1024 {
            bail!(
                "Compiled WASM is suspiciously small ({} bytes), likely compilation error",
                wasm_bytes.len()
            );
        }

        // 7. Compute hash for deduplication
        let mut hasher = Sha256::new();
        hasher.update(&wasm_bytes);
        let content_hash = hex::encode(hasher.finalize().as_slice());

        // L-16 (2026-05-22): emit a structured compile-provenance log
        // so downstream observability can correlate a content_hash with
        // the security posture under which it was produced. Three
        // dimensions matter for "is this binary still trustworthy":
        //   - dependency_allowlist_fp — fingerprint of the effective
        //     allowlist (default + extras). Tightening the allowlist
        //     between two compiles of the same source produces the
        //     same content_hash but different allowlist_fp, and
        //     operators investigating a CVE can grep both.
        //   - advisory_db_age_days — how stale the RustSec snapshot
        //     was at compile time. A "passed audit" with a 100-day-old
        //     DB is a much weaker statement than one with a fresh DB.
        //   - wit_schema_fp — fingerprint of the WIT host contract
        //     (`wit/talos.wit`) the module was bound against. A WIT
        //     bump that adds new host functions doesn't invalidate
        //     old binaries (their imports are a subset) but tracking
        //     it makes "this binary expects pre-X WIT" auditable.
        let allowlist_fp = dependency_allowlist_fingerprint();
        let advisory_db_age_days =
            advisory_db_age_days(container::ADVISORY_DB_PATH).unwrap_or(u64::MAX);
        let wit_schema_fp = wit_schema_fingerprint();
        tracing::info!(
            target: "talos_compilation_provenance",
            event_kind = "compile_provenance",
            content_hash = %content_hash,
            dependency_allowlist_fp = %allowlist_fp,
            advisory_db_age_days,
            wit_schema_fp = %wit_schema_fp,
            wasm_bytes = wasm_bytes.len(),
            "Compile provenance recorded — content_hash + security-posture fingerprints"
        );

        // 8. Inspect capability world — determines which WIT interfaces are imported.
        let inspection = talos_wit_inspector::inspect_component(&wasm_bytes);
        tracing::info!(
            capability_world = %inspection.capability_world,
            interfaces = %inspection.imported_interfaces.join(", "),
            "Capability world detected"
        );

        // 8a. Reconcile declared (source) vs detected (binary) world.
        //
        // `extract_wit_world` parses the user's source for the
        // `world = "..."` declaration; `inspect_component` inspects the
        // compiled WASM's imported interfaces and infers the
        // capability tier. The two should agree.
        //
        // Mismatch causes:
        // 1. **Typo / comment-confusion** — e.g. an out-of-date `//
        //    world: "minimal-node"` comment in the source while the
        //    actual `#[talos_module]` attribute targets `agent-node`.
        //    Most common, harmless beyond confusion.
        // 2. **Bait-and-switch** — source declares `minimal-node`
        //    (least privilege, looks safe in code review) but the
        //    macro expansion or scaffold inserts higher-tier imports.
        //    The worker's tiered linker would reject this at
        //    instantiation (the binary's imports won't resolve
        //    against the minimal-node linker), but flagging it here
        //    surfaces the bug to the operator before the module is
        //    ever dispatched.
        // 3. **Inspector limitations** — `inspect_component`
        //    classifies based on the set of imported interfaces; a
        //    binary that imports a SUBSET of its declared world's
        //    interfaces may classify as a lower tier than declared.
        //    This is benign (it means the user over-declared
        //    privileges in source but doesn't actually use them).
        //
        // We log at WARN with structured fields so operators can
        // alert on this; we do NOT fail the compile because case
        // 3 is benign and case 1/2 are surfaced anyway when the
        // worker tries to instantiate. The `talos-mcp-handlers`
        // and `talos-inline-compile-service` layers do additional
        // checks (post-compile actor capability ceiling vs detected
        // world) — this log feeds operator observability, not
        // gating.
        // wasm-security-review (2026-05-22): hard-fail when the
        // detected world is NOT a subset of the declared world (i.e.
        // the binary requested MORE privileges than the source
        // declared). Pre-fix this was a WARN-only log relying on the
        // worker's tiered linker to refuse instantiation — defense-
        // in-depth, but a bait-and-switch module would still get
        // saved to the catalog and operators wouldn't see the
        // mismatch until the first execution attempt.
        //
        // The benign case (declared > detected — user over-declared
        // privileges in source but doesn't actually use them) remains
        // a WARN. The dangerous case (detected > declared, or worlds
        // are incomparable) is a compile error.
        let detected_world_str = inspection.capability_world.to_string();
        if !declared_world.is_empty() && !detected_world_str.eq_ignore_ascii_case(declared_world) {
            let declared_enum: CapabilityWorld = declared_world
                .parse()
                .unwrap_or(CapabilityWorld::Unknown);
            // `is_subset_of` returns false when either side is
            // `Unknown`, so an unparseable declared string falls into
            // the fail-closed branch alongside genuine privilege
            // escalations — that is the safer default.
            let detected_is_subset = inspection.capability_world.is_subset_of(&declared_enum);
            if !detected_is_subset {
                let err_msg = format!(
                    "world-mismatch: source declares `{declared_world}` but the \
                     compiled binary imports `{detected_world_str}` capabilities \
                     ({interfaces}). The binary requests MORE privileges than \
                     the source attribute declares — refusing to ship. Fix the \
                     source `world = \"...\"` attribute to match what the \
                     module actually uses, or remove the unused imports.",
                    declared_world = declared_world,
                    detected_world_str = detected_world_str,
                    interfaces = inspection.imported_interfaces.join(", "),
                );
                tracing::error!(
                    declared_world = %declared_world,
                    detected_world = %detected_world_str,
                    interfaces = %inspection.imported_interfaces.join(", "),
                    module_name = %name,
                    "world-mismatch (escalation): detected world is not a \
                     subset of declared world — refusing to emit binary"
                );
                return Ok(CompilationResult {
                    success: false,
                    wasm_bytes: None,
                    errors: vec![CompilationError {
                        line: None,
                        column: None,
                        end_line: None,
                        end_column: None,
                        message: err_msg,
                        severity: "error".to_string(),
                    }],
                    size_bytes: 0,
                    content_hash: String::new(),
                    capability_world: inspection.capability_world,
                    imported_interfaces: inspection.imported_interfaces,
                });
            }
            // Benign over-declaration — source asked for more than the
            // binary uses. Still flag at WARN for operator visibility.
            tracing::warn!(
                declared_world = %declared_world,
                detected_world = %detected_world_str,
                interfaces = %inspection.imported_interfaces.join(", "),
                module_name = %name,
                "WIT world over-declared: source-declared world is more \
                 privileged than the binary actually requires. This is \
                 benign (defense in depth) but the source declaration \
                 should be tightened to the least-privilege world the \
                 module actually needs."
            );
        }

        // 9. (workspace cleanup handled by outer compile_to_wasm_with_config)
        let size_bytes = wasm_bytes.len() as i32;
        tracing::info!(
            name,
            size_bytes,
            content_hash = %content_hash,
            "compilation successful"
        );

        Ok(CompilationResult {
            success: true,
            wasm_bytes: Some(wasm_bytes),
            errors: lint_warnings, // Non-blocking warnings from static analysis
            size_bytes,
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
        let raw_package_name = name
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '-' })
            .collect::<String>()
            .to_lowercase();

        // Cargo requires every dash-separated segment to start with a letter.
        // Node IDs ending in digits (e.g. "run-string-2") would produce an invalid
        // segment "2". Prepend 'n' to any segment that starts with a digit.
        let package_name = raw_package_name
            .split('-')
            .map(|seg| {
                if seg.starts_with(|c: char| c.is_ascii_digit()) {
                    format!("n{}", seg)
                } else {
                    seg.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("-");

        // Extract the WIT world from the source so the Cargo.toml target world matches
        // exactly what the macro declared. This prevents cargo-component from guessing
        // the world and guarantees the tiered-linker security model works.
        let world = extract_wit_world(source_code);

        // Crates already present in the base Cargo.toml template — injecting them again
        // would produce a duplicate key error and abort compilation.
        // serde and serde_json are always available implicitly; wit-bindgen-rt and
        // talos_sdk_macros are internal — users should never need to declare them.
        static PRE_BUNDLED: &[&str] = &[
            "serde",
            "serde_json",
            "wit-bindgen",
            "wit-bindgen-rt",
            "talos_sdk_macros",
            "talos-sdk-macros",
        ];

        // Enforce crate allowlist before building the Cargo.toml dependency block.
        // This is a defense-in-depth check — mcp/sandbox.rs also validates at the
        // MCP layer for user-facing error messages, but enforcing here guarantees
        // no code path can bypass the allowlist regardless of how compilation is invoked.
        if let Err(allowlist_err) = crate::dependency_allowlist::validate_dependencies(dependencies)
        {
            bail!("Dependency allowlist violation: {}", allowlist_err);
        }

        let mut custom_deps = String::new();
        if let Some(serde_json::Value::Object(deps)) = dependencies {
            for (crate_name, version_val) in deps {
                if !crate_name
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                {
                    bail!("Invalid crate name: {}", crate_name);
                }

                // Skip crates that are already in the base template — declaring them
                // again produces a "duplicate key" Cargo.toml parse error.
                if PRE_BUNDLED.contains(&crate_name.as_str()) {
                    tracing::debug!(
                        crate_name,
                        "skipping pre-bundled crate in custom dependencies"
                    );
                    continue;
                }

                let version = match version_val {
                    serde_json::Value::String(s) => s,
                    _ => bail!("Invalid dependency version format for crate {}", crate_name),
                };

                // Reject characters that could break out of the TOML string literal or
                // inject new sections. Only semver-compatible characters are allowed:
                // digits, dots, hyphens, carets, tildes, asterisks, and spaces.
                if version.contains("git")
                    || version.contains("path")
                    || version.contains('{')
                    || version.contains('}')
                    || version.contains('"')
                    || version.contains('\'')
                    || version.contains('\n')
                    || version.contains('\r')
                    || version.contains('[')
                    || version.contains(']')
                    || version.contains('\\')
                {
                    bail!(
                        "Invalid dependency version for {}: contains disallowed characters",
                        crate_name
                    );
                }

                // Some crates require feature flags to unlock their primary functionality.
                // Emit a Cargo inline-table for those instead of a bare version string.
                let dep_line = match crate_name.as_str() {
                    // uuid: v4 (random) and v7 (time-ordered) generation are feature-gated.
                    // Without these flags `Uuid::new_v4()` / `Uuid::now_v7()` won't compile.
                    "uuid" => format!(
                        "uuid = {{ version = \"{}\", features = [\"v4\", \"v7\"] }}\n",
                        version
                    ),
                    // tokio: only the "rt" + "macros" features are safe in a single-threaded
                    // WASM context; "full" pulls in OS threads which aren't available in WASIP2.
                    "tokio" => format!(
                        "tokio = {{ version = \"{}\", features = [\"rt\", \"macros\", \"time\", \"sync\", \"io-util\"] }}\n",
                        version
                    ),
                    _ => format!("{} = \"{}\"\n", crate_name, version),
                };
                custom_deps.push_str(&dep_line);
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
wit-bindgen-rt = {{ version = "0.44.0", features = ["bitflags"] }}
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
# REQUIRED: wasm32-wasip2 defaults to panic = "unwind" (WASI EH is supported),
# but the WASM component model adapter uses abort-mode ABI conventions for the
# cabi_post_run / cabi_realloc boundary functions. Enabling software unwind tables
# corrupts the canonical ABI for ALL return paths — Ok(), Err(), and panic!() all
# trap with different addresses. Explicitly forcing abort-mode is mandatory.
#
# With panic = "abort":
#   - Normal returns (Ok/Err) cross the WIT boundary correctly.
#   - Panics call process::abort() → WASI stderr gets the message → the worker's
#     WASI stderr capture (BufferCapture in context.rs) reads it →
#     extract_panic_message_from_stderr() formats Err("PANIC: message").
#   - The catch_unwind in #[talos_module] / #[talos_node] is a no-op but harmless.
panic = "abort"
"#,
            package_name, custom_deps, package_name, world
        );

        tokio::fs::write(workspace.join("Cargo.toml"), cargo_toml).await?;

        // Write lib.rs
        tokio::fs::create_dir_all(workspace.join("src")).await?;
        tokio::fs::write(workspace.join("src/lib.rs"), source_code).await?;

        // Copy WIT file to the workspace root's wit directory so the macro finds it at "../wit/talos.wit"
        let ws_wit_dest = self.workspace_root.join("wit/talos.wit");
        tokio::fs::create_dir_all(self.workspace_root.join("wit"))
            .await
            .with_context(|| {
                format!(
                    "Failed to create WIT staging directory at {}",
                    self.workspace_root.join("wit").display()
                )
            })?;
        tokio::fs::copy(&self.wit_path, &ws_wit_dest)
            .await
            .with_context(|| {
                format!(
                    "Failed to copy WIT file from {} to {} (source must exist at CompilationService.wit_path — check the controller build's wit/ directory is mounted/copied into the image)",
                    self.wit_path.display(),
                    ws_wit_dest.display(),
                )
            })?;

        // Also copy it inside the package directory for cargo-component's Cargo.toml metadata
        let pkg_wit_dest = workspace.join("wit/talos.wit");
        tokio::fs::create_dir_all(workspace.join("wit"))
            .await
            .with_context(|| {
                format!(
                    "Failed to create package WIT directory at {}",
                    workspace.join("wit").display()
                )
            })?;
        tokio::fs::copy(&self.wit_path, &pkg_wit_dest)
            .await
            .with_context(|| {
                format!(
                    "Failed to copy WIT file from {} to {}",
                    self.wit_path.display(),
                    pkg_wit_dest.display(),
                )
            })?;

        Ok((workspace, package_name))
    }

    fn parse_errors(&self, stderr: &str) -> Vec<CompilationError> {
        self.parse_errors_with_offset(stderr, 0)
    }

    /// Parse rustc error output, adjusting line numbers by subtracting `line_offset`
    /// (the number of boilerplate lines prepended before the user's source code).
    ///
    /// Captures the full error block (code snippet, help text, notes) rather than
    /// just the summary line, so callers get enough context to fix the issue.
    fn parse_errors_with_offset(&self, stderr: &str, line_offset: i32) -> Vec<CompilationError> {
        // Regex to extract location from rustc output:
        //   --> src/lib.rs:LINE:COL
        static RE_LOCATION: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let re_loc = RE_LOCATION
            .get_or_init(|| regex::Regex::new(r"-->\s*src/lib\.rs:(\d+):(\d+)").unwrap());

        let mut errors = Vec::new();

        // Collect location annotations that appear on lines like:
        //   --> src/lib.rs:12:5
        // These typically appear right after the error message line.
        let lines: Vec<&str> = stderr.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            if line.contains("error:") || line.contains("error[E") {
                let mut err_line: Option<i32> = None;
                let mut err_col: Option<i32> = None;

                // Capture the full error block: from the error line until the next
                // blank line or next top-level error/warning, collecting the code
                // snippet, help text, and notes that rustc emits.
                let mut block_lines: Vec<&str> = vec![line];
                let mut j = i + 1;
                while j < lines.len() {
                    let next = lines[j];
                    // Stop at the next top-level error/warning or aborting message
                    if (next.starts_with("error") || next.starts_with("warning"))
                        && !next.starts_with("   ")
                        && j > i + 1
                    {
                        break;
                    }
                    block_lines.push(next);

                    // Extract location from this block if we haven't yet
                    if err_line.is_none() {
                        if let Some(caps) = re_loc.captures(next) {
                            if let (Ok(l), Ok(c)) = (caps[1].parse::<i32>(), caps[2].parse::<i32>())
                            {
                                // Adjust line number by subtracting boilerplate offset
                                err_line = Some((l - line_offset).max(1));
                                err_col = Some(c);
                            }
                        }
                    }
                    j += 1;
                }

                // Join the full block as the message (up to 2000 chars to avoid DB bloat)
                let full_message = block_lines.join("\n");
                let message = if full_message.len() > 2000 {
                    format!(
                        "{}...",
                        talos_text_util::truncate_at_char_boundary(&full_message, 2000)
                    )
                } else {
                    full_message
                };

                errors.push(CompilationError {
                    line: err_line,
                    column: err_col,
                    end_line: None,
                    end_column: None,
                    message,
                    severity: "error".to_string(),
                });

                // Skip past the block we just consumed
                i = j;
                continue;
            }
            i += 1;
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

/// Extract the WIT world name from the source, scanning for `world: "..."` or
/// `world = "..."` patterns.
///
/// Returns `"minimal-node"` (least-privilege, no host imports beyond
/// JSON in/out) when no world declaration is found. The previous default
/// — `"automation-node"` — silently linked the full host import set into
/// modules that omitted the annotation, granting the user code privileges
/// it never asked for. Operators who want the legacy permissive default
/// can set `TALOS_DEFAULT_WIT_WORLD=automation-node`.
fn extract_wit_world(source: &str) -> String {
    // MCP-637 (2026-05-12) + wasm-security-review (2026-05-22):
    // closes N-8 (extract_wit_world matches first occurrence
    // including comments). Pre-fix `source.find(...)` matched ANY
    // occurrence of `world: "..."` or `world = "..."`, including
    // text inside `//` line comments and `/* ... */` block comments.
    //
    // A source file like
    //
    //     /* #[talos_node(world = "automation-node")] */
    //     #[talos_node(world = "minimal-node")]
    //     pub fn run(...) { ... }
    //
    // previously resolved to "automation-node" because the block
    // comment match came first. We now strip both line AND block
    // comments before scanning. Defense-in-depth: the post-compile
    // declared-vs-detected check (in `compile_with_workspace`) hard-
    // fails when detected > declared, so any extraction mis-match
    // still surfaces as a compile error rather than silently
    // shipping a higher-privilege binary.
    let stripped = strip_all_comments(source);
    for raw_line in stripped.lines() {
        let line = strip_line_comment(raw_line);
        // Check both syntactic forms on this line.
        for marker in [r#"world: ""#, r#"world = ""#] {
            if let Some(start) = line.find(marker) {
                let rest = &line[start + marker.len()..];
                if let Some(end) = rest.find('"') {
                    return rest[..end].to_string();
                }
            }
        }
    }

    // Least-privilege default. Override via env for back-compat.
    // MCP-631: empty-env hardening — `TALOS_DEFAULT_WIT_WORLD=""` (Helm
    // placeholder) would otherwise yield an empty world that the
    // compilation pipeline rejects with a confusing "unknown world"
    // error rather than using the least-privilege default.
    talos_config::get_env("TALOS_DEFAULT_WIT_WORLD", "minimal-node")
}

/// wasm-security-review (2026-05-22): returns the offending token when
/// a template's `world = ...` declaration draws from a Handlebars
/// variable rather than a string literal. Matches both attribute and
/// comment forms (`world = "{{x}}"`, `world: "{{x}}"`). Pure function
/// for unit testing.
///
/// Matching rule: scan the comment-stripped template for either
/// `world = "` or `world: "` and inspect the following string. If the
/// string contains a Handlebars expression (`{{` … `}}`), the
/// substitution is rejected. Whitespace tolerant.
pub(crate) fn template_substitutes_world(template: &str) -> Option<String> {
    let stripped = strip_all_comments(template);
    for line in stripped.lines() {
        // Tolerate `world = "..."`, `world="..."`, `world : "..."` etc.
        // We hunt for the keyword and the literal opener `"`, then
        // look for `{{` before the closing `"`.
        for needle in ["world", "world-name"] {
            let mut search_from = 0usize;
            while let Some(found) = line[search_from..].find(needle) {
                let after = &line[search_from + found + needle.len()..];
                // Skip whitespace, then expect `=` or `:` (we accept
                // both — `world = "..."` and `world: "..."` are both
                // recognised by `extract_wit_world`).
                let after_eq = after.trim_start();
                if let Some(rest) = after_eq
                    .strip_prefix('=')
                    .or_else(|| after_eq.strip_prefix(':'))
                {
                    let after_quote = rest.trim_start();
                    if let Some(string_body) = after_quote.strip_prefix('"') {
                        if let Some(end) = string_body.find('"') {
                            let value = &string_body[..end];
                            if value.contains("{{") && value.contains("}}") {
                                return Some(value.to_string());
                            }
                            // String literal but no Handlebars
                            // substitution — fine, advance past it
                            // and keep scanning the same line for
                            // additional occurrences.
                            search_from += found + needle.len();
                            continue;
                        }
                    }
                }
                search_from += found + needle.len();
            }
        }
    }
    None
}

/// wasm-security-review (2026-05-22): replace every `/* ... */` block
/// comment with equal-length spaces, preserving the byte positions of
/// surrounding source. Block-comment-aware so it doesn't fire on
/// `let s = "/* literal */"`. Pure function for unit testing.
///
/// We replace with spaces (not removal) so any future code that
/// surfaces a byte offset back to the user (rustc spans, lint
/// positions, etc.) still points at the original location.
fn strip_all_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let mut in_str = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            out.push(b);
            if b == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1]);
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
            out.push(b);
            i += 1;
            continue;
        }
        // Open of a block comment `/*` — scan until the matching `*/`
        // and overwrite the whole region with spaces (preserve newlines
        // so line numbers don't shift).
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            // Consume the closing `*/` if present (it may not be — an
            // unterminated comment will be rejected by rustc later).
            if i + 1 < bytes.len() {
                out.push(b' ');
                out.push(b' ');
                i += 2;
            }
            continue;
        }
        out.push(b);
        i += 1;
    }
    // SAFETY: we only ever replaced non-ASCII-relevant bytes (`/` and
    // `*` from a comment region) with ASCII spaces, and we copy
    // arbitrary UTF-8 bytes through unchanged otherwise. The result is
    // valid UTF-8.
    String::from_utf8(out).unwrap_or_else(|_| source.to_string())
}

/// MCP-637: strip the `// ...` tail from a source line while
/// preserving string-literal contents. A naive `find("//").map(...)`
/// would mis-strip `let url = "https://example.com";`. Walks the line
/// once, tracking whether we're inside a string literal (respecting
/// `\"` escapes); returns the slice up to the first `//` that occurs
/// OUTSIDE a string.
fn strip_line_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_str = false;
    let mut i = 0;
    while i + 1 < bytes.len() {
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
        if b == b'/' && bytes[i + 1] == b'/' {
            return &line[..i];
        }
        i += 1;
    }
    line
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

/// Source language for a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleLanguage {
    Rust,
    JavaScript,
    TypeScript,
    /// Python via componentize-py. Requires componentize-py in PATH.
    Python,
    /// Go via TinyGo. Requires tinygo in PATH.
    Go,
}

impl ModuleLanguage {
    /// Parse a language string loosely (case-insensitive, common aliases).
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "javascript" | "js" => ModuleLanguage::JavaScript,
            "typescript" | "ts" => ModuleLanguage::TypeScript,
            "python" | "py" => ModuleLanguage::Python,
            "go" | "golang" => ModuleLanguage::Go,
            _ => ModuleLanguage::Rust,
        }
    }
}

impl std::fmt::Display for ModuleLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModuleLanguage::Rust => write!(f, "rust"),
            ModuleLanguage::JavaScript => write!(f, "javascript"),
            ModuleLanguage::TypeScript => write!(f, "typescript"),
            ModuleLanguage::Python => write!(f, "python"),
            ModuleLanguage::Go => write!(f, "go"),
        }
    }
}

// ============================================================================
// Multi-language compilation (JS / Python → WASM Component Model)
// ============================================================================

impl CompilationService {
    /// Compile JavaScript source code to a WASM Component Model binary.
    ///
    /// Uses `jco componentize` (the JavaScript Component Model toolchain) to
    /// compile JS source into a WASM component that implements the Talos WIT
    /// interface. The resulting binary is interchangeable with Rust-compiled
    /// modules — the runtime, fuel metering, and capability worlds work identically.
    ///
    /// Requires `jco` to be installed: `npm install -g @bytecodealliance/jco`
    pub async fn compile_js_to_wasm(
        &self,
        js_source: &str,
        world: &str,
        job_id: &str,
    ) -> Result<Vec<u8>> {
        // M-13: refuse host-toolchain JS compile in production unless
        // the operator has opted into the legacy degraded sandbox.
        require_host_lang_toolchain_allowed("javascript")?;

        let _permit = compilation_semaphore()
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("Compilation queue full — try again later"))?;

        let workspace = std::env::temp_dir().join(format!("talos-js-{}", job_id));
        tokio::fs::create_dir_all(&workspace).await?;

        // Write JS source
        let source_path = workspace.join("module.js");
        tokio::fs::write(&source_path, js_source).await?;

        // Copy WIT file
        let wit_dest = workspace.join("talos.wit");
        if self.wit_path.exists() {
            tokio::fs::copy(&self.wit_path, &wit_dest).await?;
        }

        let output_path = workspace.join("module.wasm");

        // Compile with jco componentize
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            Command::new("jco")
                .args([
                    "componentize",
                    source_path.to_str().unwrap_or("module.js"),
                    "--wit",
                    wit_dest.to_str().unwrap_or("talos.wit"),
                    "--world-name",
                    world,
                    "-o",
                    output_path.to_str().unwrap_or("module.wasm"),
                ])
                .current_dir(&workspace)
                .output(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("JS compilation timed out after 120s"))??;

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            // Sanitize paths in error messages
            let sanitized = stderr.replace(workspace.to_str().unwrap_or(""), "<workspace>");
            let _ = tokio::fs::remove_dir_all(&workspace).await;
            bail!("JS compilation failed:\n{}", sanitized);
        }

        let wasm_bytes = tokio::fs::read(&output_path).await?;
        let _ = tokio::fs::remove_dir_all(&workspace).await;

        // Validate the output is a valid WASM component
        if wasm_bytes.len() < 8 || &wasm_bytes[..4] != b"\0asm" {
            bail!("JS compilation produced invalid WASM binary");
        }

        tracing::info!(
            job_id = job_id,
            language = "javascript",
            output_bytes = wasm_bytes.len(),
            "JS → WASM compilation complete"
        );

        Ok(wasm_bytes)
    }

    /// Compile Python source code to a WASM Component Model binary.
    ///
    /// Uses `componentize-py` to compile Python source into a WASM component.
    /// Requires `componentize-py` to be installed: `pip install componentize-py`
    pub async fn compile_python_to_wasm(
        &self,
        python_source: &str,
        world: &str,
        job_id: &str,
    ) -> Result<Vec<u8>> {
        // M-13: refuse host-toolchain Python compile in production
        // unless the operator has opted into the legacy degraded sandbox.
        // componentize-py runs arbitrary Python introspection at compile
        // time, so this is the highest-risk of the non-Rust paths.
        require_host_lang_toolchain_allowed("python")?;

        let _permit = compilation_semaphore()
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("Compilation queue full — try again later"))?;

        let workspace = std::env::temp_dir().join(format!("talos-py-{}", job_id));
        tokio::fs::create_dir_all(&workspace).await?;

        // Write Python source
        let source_path = workspace.join("app.py");
        tokio::fs::write(&source_path, python_source).await?;

        // Copy WIT file
        let wit_dest = workspace.join("talos.wit");
        if self.wit_path.exists() {
            tokio::fs::copy(&self.wit_path, &wit_dest).await?;
        }

        let output_path = workspace.join("module.wasm");

        // Compile with componentize-py
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            Command::new("componentize-py")
                .args([
                    "-d",
                    wit_dest.to_str().unwrap_or("talos.wit"),
                    "-w",
                    world,
                    "componentize",
                    source_path.to_str().unwrap_or("app.py"),
                    "-o",
                    output_path.to_str().unwrap_or("module.wasm"),
                ])
                .current_dir(&workspace)
                .output(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Python compilation timed out after 120s"))??;

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            let sanitized = stderr.replace(workspace.to_str().unwrap_or(""), "<workspace>");
            let _ = tokio::fs::remove_dir_all(&workspace).await;
            bail!("Python compilation failed:\n{}", sanitized);
        }

        let wasm_bytes = tokio::fs::read(&output_path).await?;
        let _ = tokio::fs::remove_dir_all(&workspace).await;

        if wasm_bytes.len() < 8 || &wasm_bytes[..4] != b"\0asm" {
            bail!("Python compilation produced invalid WASM binary");
        }

        tracing::info!(
            job_id = job_id,
            language = "python",
            output_bytes = wasm_bytes.len(),
            "Python → WASM compilation complete"
        );

        Ok(wasm_bytes)
    }
}

/// Auto-detect the source language from the source code content.
pub fn detect_language(source_code: &str) -> ModuleLanguage {
    // TypeScript indicators
    if source_code.contains(": string")
        || source_code.contains(": number")
        || source_code.contains(": boolean")
        || source_code.contains("interface ")
        || source_code.contains(": void")
    {
        return ModuleLanguage::TypeScript;
    }
    // Go indicators
    if source_code.contains("package main")
        || source_code.contains("func Run(")
        || (source_code.contains("func ") && source_code.contains("import ("))
    {
        return ModuleLanguage::Go;
    }
    // Python indicators
    if source_code.contains("def run(")
        || source_code.contains("import json")
        || source_code.contains("from talos")
        || (source_code.contains("def ") && !source_code.contains("fn "))
    {
        return ModuleLanguage::Python;
    }
    // JavaScript indicators
    if source_code.contains("export function")
        || source_code.contains("export async function")
        || source_code.contains("module.exports")
        || source_code.contains("const ")
            && !source_code.contains("fn ")
            && !source_code.contains("let mut")
    {
        return ModuleLanguage::JavaScript;
    }
    ModuleLanguage::Rust
}

impl CompilationService {
    /// Fast syntax/type check without full compilation.
    /// Uses `cargo check` instead of `cargo component build --release`, so it
    /// skips code-gen, linking and Wizer snapshotting. Typically 3-5x faster.
    pub async fn lint_code(
        &self,
        name: &str,
        source_code: &str,
        world: &str,
        dependencies: Option<&serde_json::Value>,
    ) -> Result<Vec<CompilationError>> {
        // Static-lint pre-pass first — instant, no compile semaphore needed.
        // Mirrors compile_to_wasm_with_config so domain-specific hints
        // (e.g. `secrets::get` → `secrets::get_secret`) surface from BOTH
        // the lint pre-flight and the full compile path.
        let static_lints = analyze::lint_source_code(source_code);
        let static_errors: Vec<CompilationError> = static_lints
            .iter()
            .filter(|e| e.severity == "error")
            .cloned()
            .collect();
        if !static_errors.is_empty() {
            return Ok(static_errors);
        }

        // Acquire compilation permit (same semaphore as full builds)
        let _permit = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            compilation_semaphore().acquire(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Lint queue full. Try again shortly."))?
        .map_err(|_| anyhow::anyhow!("Compilation semaphore closed"))?;

        // Inject the talos_node macro preamble only when the source does not
        // already carry a proc-macro annotation.  The sandbox codegen in
        // mcp/sandbox.rs may have already injected
        // `#[talos_sdk_macros::talos_module(world = "...")]`.  Adding a second
        // macro on top causes E0428 "defined multiple times" errors for every
        // item both macros try to emit (15+ with the log_json WIT addition).
        let already_annotated = source_code.contains("#[talos_node")
            || source_code.contains("talos_sdk_macros::talos_node")
            || source_code.contains("#[talos_module")
            || source_code.contains("talos_sdk_macros::talos_module")
            || source_code.contains("wit_bindgen::generate!");

        let (full_source, preamble_lines) = if already_annotated {
            (source_code.to_string(), 0usize)
        } else {
            // Inject the annotation specifically before `fn run` (not the first fn)
            // so that helper functions defined before `run` don't absorb the macro.
            static RE_RUN_FN_LINT: std::sync::LazyLock<regex::Regex> =
                std::sync::LazyLock::new(|| {
                    regex::Regex::new(r"(?m)^[ \t]*(pub[ \t]+)?fn[ \t]+run[ \t]*\(").unwrap()
                });
            let use_line = "use talos_sdk_macros::talos_node;\n";
            let annotation = format!("#[talos_node(world = \"{world}\")]\n");
            match RE_RUN_FN_LINT.find(source_code) {
                Some(m) => {
                    // Helpers before `fn run` are shifted by 1 (the use line only).
                    // `fn run` and lines after it are shifted by 2 (use + annotation).
                    // Report preamble as 1 — helpers get correct line numbers; `run`
                    // errors are off by 1 which is acceptable for the lint fast-path.
                    let code = format!(
                        "{use_line}{}{}{}",
                        &source_code[..m.start()],
                        annotation,
                        &source_code[m.start()..]
                    );
                    (code, 1usize)
                }
                None => {
                    // No `fn run` found — fall back to original prepend
                    (format!("{use_line}{annotation}{source_code}"), 2usize)
                }
            }
        };

        let job_id = Uuid::new_v4();
        let (workspace, _package_name) = self
            .create_workspace(job_id, name, &full_source, dependencies)
            .await?;

        // Run `cargo component check` (NOT plain `cargo check`).
        // Plain `cargo check` does not invoke cargo-component's build pipeline, so
        // `src/bindings.rs` is never generated. The proc macro
        // `#[talos_module]` expands to `include!(concat!(..., "/src/bindings.rs"))`,
        // which fails with "No such file or directory" — manifesting as a confusing
        // lint error on every run_sandbox call. `cargo component check` generates
        // bindings first, then delegates to `cargo check` for the type check.
        //
        // When container isolation is enabled, lint also runs inside the builder
        // container for consistency (same toolchain, same isolation).
        let cargo_registry_cache = dirs_next::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join(".cargo/registry");
        let wit_dir = self
            .wit_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let lint_cmd = container::build_command(&workspace, &cargo_registry_cache, wit_dir);
        let output = match lint_cmd {
            Ok(mut cmd) => tokio::time::timeout(
                std::time::Duration::from_secs(30),
                cmd.args(&[
                    "component",
                    "check",
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
            .context("Lint check timed out after 30 seconds")?,
            Err(e) => {
                // MCP-148 (2026-05-08): Honor the production fail-closed
                // policy. `container::build_command` already bails with a
                // clear "install podman/docker OR set
                // TALOS_COMPILATION_ALLOW_HOST_FALLBACK=true" message in
                // production-no-runtime mode. Pre-fix this arm silently
                // ran direct cargo on the host (running build.rs +
                // proc-macros from talos_sdk_macros + any user deps OUTSIDE
                // any sandbox), and the static-only-lints emptiness made
                // the response look like "lint passed" even though the
                // cargo check never ran the way the policy required.
                // Match compile_custom_sandbox: propagate the bail in
                // production unless the operator opted into host
                // fallback. Non-production stays on the legacy direct
                // cargo path.
                if talos_config::is_production()
                    && !container::host_fallback_allowed()
                {
                    return Err(e).context("Lint check requires container compilation in production");
                }
                tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    Command::new("cargo")
                        .args(&[
                            "component",
                            "check",
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
                .context("Lint check timed out after 30 seconds")?
            }
        }?;

        let errors = if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let workspace_prefix = workspace.to_str().unwrap_or("");
            let sanitized_stderr = if workspace_prefix.is_empty() {
                stderr.to_string()
            } else {
                stderr.replace(workspace_prefix, "<workspace>")
            };
            self.parse_errors_with_offset(&sanitized_stderr, preamble_lines as i32)
        } else {
            vec![]
        };

        // Clean up workspace
        tokio::fs::remove_dir_all(&workspace).await.ok();

        Ok(errors)
    }

    /// Compile source to WASM with an explicit language override.
    ///
    /// - `Rust` / `None`: standard `cargo component build` path
    /// - `Python`: `componentize-py` targeting the specified world
    /// - `JavaScript` / `TypeScript` / `Go`: stub — falls back to Rust path
    pub async fn compile_to_wasm_with_language(
        &self,
        user_id: Uuid,
        job_id: Uuid,
        name: &str,
        source_code: &str,
        config: &serde_json::Value,
        dependencies: Option<&serde_json::Value>,
        language: Option<ModuleLanguage>,
    ) -> Result<CompilationResult> {
        match language {
            Some(ModuleLanguage::Python) => {
                self.compile_python_module(user_id, job_id, name, source_code, config)
                    .await
            }
            _ => {
                self.compile_to_wasm_with_config(
                    user_id,
                    job_id,
                    name,
                    source_code,
                    config,
                    dependencies,
                )
                .await
            }
        }
    }

    /// Compile a Python module to WASM via `componentize-py`.
    ///
    /// The Python source is written to a temporary workspace, then
    /// `componentize-py` is invoked with the appropriate WIT world.
    /// The resulting WASM component is read and returned.
    async fn compile_python_module(
        &self,
        user_id: Uuid,
        job_id: Uuid,
        name: &str,
        source_code: &str,
        config: &serde_json::Value,
    ) -> Result<CompilationResult> {
        // M-13: same fail-closed gate as compile_python_to_wasm. This
        // path is the one hit by `compile_to_wasm_with_language` so
        // gating both entrypoints means there's no surface that can
        // reach `componentize-py` on the host without the explicit
        // operator opt-in.
        require_host_lang_toolchain_allowed("python")?;

        self.send_event(
            user_id,
            job_id,
            "starting",
            Some("Initializing Python compilation environment...".to_string()),
            Some(0.05),
        );
        let _permit = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            compilation_semaphore().acquire(),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "Python compilation queue full (max {} concurrent). Try again later.",
                compilation_semaphore().available_permits()
                    + std::env::var("TALOS_MAX_COMPILATIONS")
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(3)
            )
        })?
        .map_err(|e| anyhow::anyhow!("Semaphore error: {}", e))?;

        // Create temp workspace
        let workspace = self
            .workspace_root
            .join(format!("py-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&workspace).await?;

        // Run the compilation in a closure so we can ensure cleanup on all exit paths.
        let result = self
            .compile_python_inner(user_id, job_id, name, source_code, config, &workspace)
            .await;

        // Cleanup workspace on ALL paths (success, error, early return).
        tokio::fs::remove_dir_all(&workspace).await.ok();

        result
    }

    /// Inner Python compilation logic — separated so the caller can guarantee cleanup.
    async fn compile_python_inner(
        &self,
        user_id: Uuid,
        job_id: Uuid,
        name: &str,
        source_code: &str,
        config: &serde_json::Value,
        workspace: &std::path::Path,
    ) -> Result<CompilationResult> {
        self.send_event(
            user_id,
            job_id,
            "compiling",
            Some("Detecting Python capability world...".to_string()),
            Some(0.1),
        );
        let world =
            Self::detect_python_world(source_code).unwrap_or_else(|| "minimal-node".to_string());

        // Write Python source
        let app_path = workspace.join("app.py");
        tokio::fs::write(&app_path, source_code).await?;

        // Write the WIT file alongside the source
        let wit_dir = workspace.join("wit");
        tokio::fs::create_dir_all(&wit_dir).await?;
        let wit_source_path = self
            .workspace_root
            .parent()
            .unwrap_or(&self.workspace_root)
            .join("wit")
            .join("talos.wit");
        if tokio::fs::metadata(&wit_source_path).await.is_ok() {
            tokio::fs::copy(&wit_source_path, wit_dir.join("talos.wit")).await?;
        }

        // Output path
        let output_wasm = workspace.join("output.wasm");

        // Build componentize-py command
        let mut cmd = tokio::process::Command::new("componentize-py");
        cmd.args([
            "-d",
            wit_dir.to_str().unwrap_or("wit"),
            "-w",
            &format!("talos:core/{}", world),
            "componentize",
            "app",
            "-o",
            output_wasm.to_str().unwrap_or("output.wasm"),
        ]);
        cmd.current_dir(&workspace);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        tracing::info!(
            name = %name,
            world = %world,
            "Compiling Python module via componentize-py"
        );
        self.send_event(
            user_id,
            job_id,
            "compiling",
            Some("Invoking componentize-py...".to_string()),
            Some(0.4),
        );

        let result = tokio::time::timeout(std::time::Duration::from_secs(120), cmd.output())
            .await
            .map_err(|_| anyhow::anyhow!("Python compilation timed out after 120 seconds"))?
            .context("Failed to execute componentize-py")?;

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            let stdout = String::from_utf8_lossy(&result.stdout);
            let error_text = if stderr.is_empty() {
                stdout.to_string()
            } else {
                stderr.to_string()
            };

            return Ok(CompilationResult {
                success: false,
                wasm_bytes: None,
                errors: vec![CompilationError {
                    line: None,
                    column: None,
                    end_line: None,
                    end_column: None,
                    message: error_text,
                    severity: "error".to_string(),
                }],
                size_bytes: 0,
                content_hash: String::new(),
                capability_world: CapabilityWorld::Unknown,
                imported_interfaces: vec![],
            });
        }

        // Read the compiled WASM
        let wasm_bytes = tokio::fs::read(&output_wasm).await.ok();
        let size_bytes = wasm_bytes.as_ref().map(|b| b.len() as i32).unwrap_or(0);
        let content_hash = wasm_bytes
            .as_ref()
            .map(|b| hex::encode(sha2::Sha256::digest(b)))
            .unwrap_or_default();

        // Validate WASM if present
        if let Some(ref bytes) = wasm_bytes {
            if bytes.len() < 8 {
                return Ok(CompilationResult {
                    success: false,
                    wasm_bytes: None,
                    errors: vec![CompilationError {
                        line: None,
                        column: None,
                        end_line: None,
                        end_column: None,
                        message: "componentize-py produced invalid WASM (too small)".to_string(),
                        severity: "error".to_string(),
                    }],
                    size_bytes: 0,
                    content_hash: String::new(),
                    capability_world: CapabilityWorld::Unknown,
                    imported_interfaces: vec![],
                });
            }
        }

        // Map world string to CapabilityWorld enum
        let cap_world = world
            .parse::<CapabilityWorld>()
            .unwrap_or(CapabilityWorld::Unknown);

        tracing::info!(
            name = %name,
            world = %world,
            size_bytes = size_bytes,
            "Python module compiled successfully"
        );

        Ok(CompilationResult {
            success: wasm_bytes.is_some(),
            wasm_bytes,
            errors: vec![],
            size_bytes,
            content_hash,
            capability_world: cap_world,
            imported_interfaces: vec![],
        })
    }

    /// Extract the capability world from Python source code.
    ///
    /// Looks for `@talos_module(world="...")` or `__talos_world__ = "..."`.
    fn detect_python_world(source: &str) -> Option<String> {
        // Pattern 1: @talos_module(world="http-node")
        if let Some(idx) = source.find("@talos_module") {
            let after = &source[idx..];
            if let Some(w_start) = after.find("world=") {
                let rest = &after[w_start + 6..];
                let quote = rest.chars().next()?;
                if quote == '"' || quote == '\'' {
                    let end = rest[1..].find(quote)?;
                    return Some(rest[1..1 + end].to_string());
                }
            }
        }
        // Pattern 2: __talos_world__ = "http-node"
        if let Some(idx) = source.find("__talos_world__") {
            let after = &source[idx..];
            if let Some(eq) = after.find('=') {
                let rest = after[eq + 1..].trim_start();
                let quote = rest.chars().next()?;
                if quote == '"' || quote == '\'' {
                    let end = rest[1..].find(quote)?;
                    return Some(rest[1..1 + end].to_string());
                }
            }
        }
        None
    }
}

/// Summary of `cargo audit --json` output for error reporting.
struct AuditSummary {
    count: usize,
    names: Vec<String>,
}

/// Parse `cargo audit --json` stdout into a compact summary.
///
/// Returns an empty summary on any parse error (fail-open for reporting
/// only — production tool-failure detection is at the call site, which
/// hard-bails when status != 0 + count == 0). Distinguishes "no JSON at
/// all" from "valid JSON, no vulnerabilities key" so operators can detect
/// schema drift in `cargo audit`'s output without the silent fail-open
/// masking the underlying issue.
fn parse_audit_summary(stdout: &[u8]) -> AuditSummary {
    let v = match serde_json::from_slice::<serde_json::Value>(stdout) {
        Ok(v) => v,
        Err(e) => {
            // Snippet — first 256 bytes — so the operator can spot the
            // offending output without flooding logs. Don't include the
            // whole stdout (could be MB if cargo dumped a stack trace).
            let snippet: String = String::from_utf8_lossy(stdout)
                .chars()
                .take(256)
                .collect();
            tracing::warn!(
                target: "talos_compilation",
                event_kind = "audit_parse_failure",
                error = %e,
                stdout_snippet = %snippet,
                "cargo-audit stdout was not valid JSON — possible schema drift; \
                 vulnerability detection is fail-open for this run"
            );
            return AuditSummary {
                count: 0,
                names: vec![],
            };
        }
    };

    if v.pointer("/vulnerabilities").is_none() {
        // Valid JSON but no vulnerabilities key → schema may have moved.
        // Distinct from the missing-count case below (where the key
        // exists but the count is absent or zero).
        let snippet: String = String::from_utf8_lossy(stdout)
            .chars()
            .take(256)
            .collect();
        tracing::warn!(
            target: "talos_compilation",
            event_kind = "audit_parse_failure",
            schema_drift = "missing_vulnerabilities_key",
            stdout_snippet = %snippet,
            "cargo-audit JSON missing /vulnerabilities key — schema drift"
        );
        return AuditSummary {
            count: 0,
            names: vec![],
        };
    }

    let count = v
        .pointer("/vulnerabilities/count")
        .and_then(|c| c.as_u64())
        .unwrap_or(0) as usize;

    let names: Vec<String> = v
        .pointer("/vulnerabilities/list")
        .and_then(|l| l.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|entry| {
                    let id = entry.pointer("/advisory/id").and_then(|v| v.as_str());
                    let pkg = entry.pointer("/advisory/package").and_then(|v| v.as_str());
                    match (id, pkg) {
                        (Some(id), Some(pkg)) => Some(format!("{id}({pkg})")),
                        (Some(id), None) => Some(id.to_string()),
                        (None, Some(pkg)) => Some(pkg.to_string()),
                        _ => None,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    AuditSummary { count, names }
}

#[cfg(test)]
mod extract_wit_world_tests {
    use super::extract_wit_world;

    /// MCP-637: a line comment containing the marker must NOT be
    /// matched. The real attribute on the next line is the source of
    /// truth.
    #[test]
    fn ignores_line_comment_above_real_attribute() {
        let source = r#"
// world: "minimal-node" — see talos.wit for the full set
#[talos_node(world = "automation-node")]
pub fn run() {}
"#;
        assert_eq!(extract_wit_world(source), "automation-node");
    }

    /// MCP-637: trailing line comment with the marker on the same
    /// physical line as a real attribute must not steal precedence
    /// from a real attribute on a LATER line.
    #[test]
    fn ignores_trailing_line_comment() {
        let source = r#"
let x = 1; // world: "minimal-node" — bogus
#[talos_node(world = "agent-node")]
pub fn run() {}
"#;
        assert_eq!(extract_wit_world(source), "agent-node");
    }

    /// MCP-637: string-literal `//` does not count as a comment start.
    /// Make sure the comment-stripper preserves the marker that's
    /// inside a string literal earlier on the same line.
    #[test]
    fn preserves_marker_inside_string_literal() {
        let source = r#"
let url = "https://example.com/world: \"minimal-node\""; #[talos_node(world = "network-node")] fn run() {}
"#;
        // The escaped `\"` quotes inside the string keep the comment-
        // stripper from terminating early; the colon-form marker
        // appears inside a string literal so it would NOT be a match
        // candidate even without the line-comment stripping. The
        // equals-form `world = "network-node"` after `; #[talos_node(...)`
        // wins.
        assert_eq!(extract_wit_world(source), "network-node");
    }

    /// Existing behavior — colon and equals forms both work, default
    /// kicks in when neither is present.
    #[test]
    fn colon_form_matches() {
        assert_eq!(
            extract_wit_world(r#"talos.wit world: "agent-node""#),
            "agent-node"
        );
    }

    #[test]
    fn equals_form_matches() {
        assert_eq!(
            extract_wit_world(r#"#[talos_node(world = "http-node")] fn run() {}"#),
            "http-node"
        );
    }

    #[test]
    fn default_when_no_marker() {
        // Without RUST_ENV or TALOS_DEFAULT_WIT_WORLD set, default
        // is "minimal-node" (least-privilege).
        std::env::remove_var("TALOS_DEFAULT_WIT_WORLD");
        assert_eq!(
            extract_wit_world("pub fn run() {}"),
            "minimal-node"
        );
    }

    /// wasm-security-review (2026-05-22): block comment containing
    /// the marker must NOT win over a real attribute on a later line.
    /// Pre-fix this returned `automation-node`.
    #[test]
    fn ignores_block_comment_above_real_attribute() {
        let source = r#"
/* #[talos_node(world = "automation-node")] */
#[talos_node(world = "minimal-node")]
pub fn run() {}
"#;
        assert_eq!(extract_wit_world(source), "minimal-node");
    }

    /// Multi-line block comment with the marker inside is stripped
    /// before scanning. The real attribute below wins.
    #[test]
    fn ignores_multiline_block_comment() {
        let source = r#"
/*
 * Some documentation that mentions world = "automation-node"
 * for illustrative purposes.
 */
#[talos_node(world = "http-node")]
pub fn run() {}
"#;
        assert_eq!(extract_wit_world(source), "http-node");
    }

    /// String literal containing `/* */` markers is NOT treated as a
    /// comment region. Defense against the `strip_all_comments`
    /// being fooled by `"// /* x */"` inside a string.
    #[test]
    fn block_comment_inside_string_literal_is_preserved() {
        let source = r#"
let s = "/* world = \"automation-node\" */";
#[talos_node(world = "secrets-node")]
pub fn run() {}
"#;
        assert_eq!(extract_wit_world(source), "secrets-node");
    }
}

#[cfg(test)]
mod template_world_injection_tests {
    use super::template_substitutes_world;

    #[test]
    fn detects_attribute_form_substitution() {
        let template = r#"
// handlebars: true
#[talos_node(world = "{{user_world}}")]
pub fn run() {}
"#;
        assert!(template_substitutes_world(template).is_some());
    }

    #[test]
    fn detects_colon_form_substitution() {
        let template = r#"
// handlebars: true
// world: "{{user_world}}"
pub fn run() {}
"#;
        assert!(template_substitutes_world(template).is_some());
    }

    #[test]
    fn allows_literal_world_string() {
        let template = r#"
// handlebars: true
#[talos_node(world = "http-node")]
pub fn run() {}
"#;
        assert_eq!(template_substitutes_world(template), None);
    }

    #[test]
    fn allows_handlebars_in_unrelated_string() {
        let template = r#"
// handlebars: true
const KEY: &str = "{{api_key}}";
#[talos_node(world = "http-node")]
pub fn run() {}
"#;
        assert_eq!(template_substitutes_world(template), None);
    }

    #[test]
    fn block_comment_with_world_substitution_still_blocked() {
        // A template that hides a `world = "{{...}}"` inside a block
        // comment shouldn't matter (it wouldn't reach extract_wit_world
        // either, since strip_all_comments removes it). But we still
        // want template_substitutes_world to be paranoid about
        // ANY world = "{{...}}" form regardless of context, because
        // a stray Handlebars expression next to the `world` keyword
        // is suspicious. The current impl strips comments before
        // scanning, so this returns None — that's the conservative
        // behaviour: defer to extract_wit_world and the post-compile
        // detected-vs-declared check, both of which run on the
        // post-comment-stripped source.
        let template = r#"
// handlebars: true
/* world = "{{user_world}}" */
#[talos_node(world = "http-node")]
pub fn run() {}
"#;
        assert_eq!(template_substitutes_world(template), None);
    }
}

#[cfg(test)]
mod m13_gate_tests {
    use super::*;
    // Shared with container::tests; serialises every test in this
    // crate that mutates process env vars so they don't race in
    // parallel mode. See container::TEST_ENV_LOCK for rationale.
    use crate::container::env_lock;

    #[test]
    fn gate_no_op_in_dev() {
        let _g = env_lock();
        // Default test env is non-production; gate must not block.
        // (talos_config::is_production reads RUST_ENV=production; cargo
        // test runs without that.)
        let _orig = std::env::var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK").ok();
        std::env::remove_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK");
        assert!(require_host_lang_toolchain_allowed("python").is_ok());
        assert!(require_host_lang_toolchain_allowed("javascript").is_ok());
    }

    #[test]
    fn gate_error_message_names_language_and_env_var() {
        let _g = env_lock();
        // Force production via env var so we exercise the gate.
        let prev_env = std::env::var("RUST_ENV").ok();
        let prev_flag = std::env::var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK").ok();
        std::env::set_var("RUST_ENV", "production");
        std::env::remove_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK");

        let err = require_host_lang_toolchain_allowed("python")
            .expect_err("expected gate to refuse in production");
        let msg = format!("{err}");
        assert!(msg.contains("python"), "missing language: {msg}");
        assert!(
            msg.contains("TALOS_COMPILATION_ALLOW_HOST_FALLBACK"),
            "missing env var hint: {msg}"
        );
        assert!(
            msg.contains("multi-tenant"),
            "missing security rationale: {msg}"
        );
        assert!(
            msg.contains("disabled in production"),
            "missing posture summary: {msg}"
        );

        // Restore env.
        match prev_env {
            Some(v) => std::env::set_var("RUST_ENV", v),
            None => std::env::remove_var("RUST_ENV"),
        }
        match prev_flag {
            Some(v) => std::env::set_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK", v),
            None => std::env::remove_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK"),
        }
    }

    #[test]
    fn gate_opt_in_allows_with_warning() {
        let _g = env_lock();
        let prev_env = std::env::var("RUST_ENV").ok();
        let prev_flag = std::env::var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK").ok();
        std::env::set_var("RUST_ENV", "production");
        std::env::set_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK", "true");

        assert!(require_host_lang_toolchain_allowed("javascript").is_ok());

        match prev_env {
            Some(v) => std::env::set_var("RUST_ENV", v),
            None => std::env::remove_var("RUST_ENV"),
        }
        match prev_flag {
            Some(v) => std::env::set_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK", v),
            None => std::env::remove_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK"),
        }
    }
}
