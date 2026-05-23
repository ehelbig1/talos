//! Compilation container isolation for Talos WASM module builds.
//!
//! Wraps `cargo component build` (and `cargo audit`) in a rootless Podman (or
//! Docker) container to prevent proc-macro escape from the WASM sandbox.
//!
//! The container runs with `--network=none`, `--read-only`, memory/cpu limits,
//! and a non-root user. User-supplied Rust code never executes on the host.
//!
//! # Configuration
//!
//! - `TALOS_COMPILATION_CONTAINER` — `"true"` (default in production) or
//!   `"false"` (default in development). When `"false"`, compilation falls back
//!   to a direct `cargo` invocation on the host.
//! - `TALOS_BUILDER_IMAGE` — Container image name. Default: `talos-builder:latest`.
//! - `TALOS_BUILDER_MEMORY` — Memory limit. Default: `2g`.
//! - `TALOS_BUILDER_CPUS` — CPU limit. Default: `2`.

use std::path::Path;

use anyhow::{bail, Context, Result};
use tokio::process::Command;

/// The default container image built by `scripts/build-compiler-image.sh`.
const DEFAULT_IMAGE: &str = "talos-builder:latest";

/// Stable, image-baked path of the RustSec advisory database. Both
/// `controller/Dockerfile` (the runtime/fallback) and `Dockerfile.builder`
/// (the network-isolated sandbox) stage the DB here at image build time.
/// The compilation service passes this via `cargo audit --db <PATH>` so
/// the path is explicit, not derived from $CARGO_HOME (which the runtime
/// points at a tmpfs that gets wiped per pod).
pub const ADVISORY_DB_PATH: &str = "/opt/talos-advisory-db";

/// Default memory limit for the compilation container.
const DEFAULT_MEMORY: &str = "2g";

/// Default CPU limit for the compilation container.
const DEFAULT_CPUS: &str = "2";

/// MCP-753 (2026-05-13): read an env var and treat empty strings as
/// unset. Helm placeholder pattern (`TALOS_BUILDER_MEMORY: ""` in
/// values.yaml when the operator hasn't overridden the override)
/// makes `std::env::var(...)` return `Ok("")`, which the natural
/// `unwrap_or_else(|_| default)` path then PASSES THROUGH because
/// the closure only fires on `Err`. Without this helper, an empty
/// env value flowed verbatim into the container runtime as
/// `podman run ... --memory "" --cpus "" ...` and the container
/// failed to start with an opaque exit code 125 / "invalid memory
/// format" — operators saw "compilation failed" with no clean
/// attribution to the misconfigured env var. Same empty-env class
/// as MCP-590/591/653/710/752.
fn nonempty_env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// Returns `true` when compilation should run inside a container.
///
/// Checks `TALOS_COMPILATION_CONTAINER` env var first; falls back to
/// production = true, development = false.
fn container_enabled() -> bool {
    match std::env::var("TALOS_COMPILATION_CONTAINER") {
        Ok(val) => !matches!(val.to_lowercase().as_str(), "false" | "0" | "no"),
        Err(_) => talos_config::is_production(),
    }
}

/// Returns `true` when the operator has explicitly opted in to running
/// `cargo` directly on the host when no container runtime is available.
///
/// Default: `false`. When unset and we're in production, missing-runtime
/// fail-closes (refuses to compile) — see `build_command` and
/// `audit_command`. Single-tenant operators who accept the trust model
/// (operator authors all modules) can set
/// `TALOS_COMPILATION_ALLOW_HOST_FALLBACK=true` to restore the legacy
/// degraded-sandbox behaviour. Multi-tenant deploys MUST leave it unset
/// — running user-supplied `build.rs` / proc-macros on the host is a
/// trivial RCE escalation path.
///
/// Wasm-security review 2026-05-23 (L-finding-6): the prior gate
/// accepted `true`/`1`/`yes` in production with only a startup-time
/// WARN. That's the same value an operator might set in a dev
/// `.env` file and accidentally inherit into a production rollout —
/// the WARN is easy to miss in log-volume environments and there's
/// no second-factor on the gate. In production we now require a
/// deliberate acknowledgement token that names the risk, so the
/// flag cannot be enabled by reflex / copy-paste from a dev config:
///
///   prod: `TALOS_COMPILATION_ALLOW_HOST_FALLBACK=acknowledge-single-tenant-rce-risk`
///   dev:  `TALOS_COMPILATION_ALLOW_HOST_FALLBACK=true` (or 1 / yes / the ack token)
///
/// Existing single-tenant production operators who had `=true` will
/// see a clear startup error pointing them at the new value — they
/// keep the same opt-in capability, the muscle-memory just costs
/// one extra step. The ack token is also accepted in dev so an
/// operator can mirror prod config locally for validation.
const HOST_FALLBACK_PROD_ACK: &str = "acknowledge-single-tenant-rce-risk";

pub fn host_fallback_allowed() -> bool {
    let raw = match std::env::var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK") {
        Ok(v) => v,
        Err(_) => return false,
    };
    let normalized = raw.trim().to_ascii_lowercase();
    // Production: ONLY the explicit ack token counts. true/1/yes are
    // ignored (with a loud WARN) so an operator who carried a dev value
    // into prod sees the safer "compilation refused" outcome rather than
    // silently running unsandboxed.
    if talos_config::is_production() {
        if normalized == HOST_FALLBACK_PROD_ACK {
            return true;
        }
        if matches!(normalized.as_str(), "true" | "1" | "yes") {
            tracing::warn!(
                target: "talos_compilation",
                event_kind = "host_fallback_prod_short_form_rejected",
                value = %normalized,
                expected = HOST_FALLBACK_PROD_ACK,
                "TALOS_COMPILATION_ALLOW_HOST_FALLBACK is set to a short-form truthy value \
                 in production; this is ignored. To enable the unsandboxed fallback in \
                 production set the value to the explicit ack token (see \
                 host_fallback_allowed doc-comment). The short-form values remain accepted \
                 in dev/CI for ergonomic mirroring."
            );
        }
        return false;
    }
    // Dev/CI: short-form values keep working so existing test fixtures
    // and local `.env` files don't break. The ack token also works so
    // operators can mirror prod config locally.
    matches!(
        normalized.as_str(),
        "true" | "1" | "yes" | HOST_FALLBACK_PROD_ACK
    )
}

/// Detect which container runtime is available on the host.
///
/// Prefers `podman` (rootless by default); falls back to `docker`.
/// Returns `None` if neither is found.
fn detect_runtime() -> Option<&'static str> {
    // Quick check: try `podman --version` then `docker --version`.
    // Using sync Command because this runs once at startup and the result is
    // used to configure the async build command.
    for candidate in &["podman", "docker"] {
        let result = std::process::Command::new(candidate)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if let Ok(status) = result {
            if status.success() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Build a [`Command`] that runs `cargo` inside an isolated container.
///
/// The returned command is pre-configured with security flags but has no
/// arguments yet — the caller appends `cargo component build ...` or
/// `cargo audit ...` arguments.
///
/// # Arguments
///
/// * `workspace` — The temporary compilation workspace directory (mounted read-write).
/// * `cargo_registry_cache` — Host-side Cargo registry cache (mounted read-only for speed).
/// * `wit_dir` — Directory containing the WIT files (mounted read-only).
///
/// # Fallback
///
/// When `TALOS_COMPILATION_CONTAINER=false` (or neither podman nor docker is
/// found in a non-production environment), returns a plain `Command::new("cargo")`
/// that runs directly on the host.
pub fn build_command(
    workspace: &Path,
    cargo_registry_cache: &Path,
    wit_dir: &Path,
) -> Result<Command> {
    if !container_enabled() {
        tracing::debug!("Container compilation disabled — using direct cargo");
        return Ok(Command::new("cargo"));
    }

    let runtime = match detect_runtime() {
        Some(rt) => {
            tracing::info!(runtime = rt, "Container compilation enabled");
            rt
        }
        None => {
            // In production we fail-closed by default — running user-supplied
            // `build.rs` / proc-macros on the host pod is arbitrary code
            // execution outside the WASM sandbox, trivially escalatable to
            // RCE. Single-tenant operators who accept the trust model can
            // opt back into the degraded-sandbox path by setting
            // `TALOS_COMPILATION_ALLOW_HOST_FALLBACK=true`. This matches
            // `audit_command`'s production policy.
            if talos_config::is_production() && !host_fallback_allowed() {
                bail!(
                    "Container compilation is required in production but neither \
                     podman nor docker was found in PATH. Install a container \
                     runtime in the controller pod to restore sandboxing. \
                     Single-tenant operators who accept the trust model (operator \
                     authors all modules — user-supplied proc-macros run on the \
                     controller host) can set \
                     TALOS_COMPILATION_ALLOW_HOST_FALLBACK=acknowledge-single-tenant-rce-risk \
                     to permit the legacy unsandboxed fallback. The short-form values \
                     (`true`/`1`/`yes`) accepted in dev are intentionally REFUSED in \
                     production to prevent accidental dev-config inheritance — see \
                     `host_fallback_allowed` in talos-compilation/src/container.rs."
                );
            }
            if talos_config::is_production() {
                // Opt-in fallback. Loud WARN so operators can correlate any
                // proc-macro escape with the missing sandbox; emit a
                // structured event under target = "talos_compilation" so
                // dashboards can alert on the rate.
                tracing::warn!(
                    target: "talos_compilation",
                    event_kind = "compilation_unsandboxed_fallback",
                    fallback_reason = "no_runtime",
                    "Container compilation enabled but no runtime (podman/docker) \
                     found in PATH — FALLING BACK to direct cargo in production \
                     because TALOS_COMPILATION_ALLOW_HOST_FALLBACK=true. \
                     Modules are compiling WITHOUT container isolation. \
                     This is operator-acknowledged for single-tenant deploys; \
                     UNSAFE for multi-tenant."
                );
            } else {
                tracing::warn!(
                    "Container compilation enabled but no runtime found — \
                     falling back to direct cargo in non-production mode"
                );
            }
            return Ok(Command::new("cargo"));
        }
    };

    let image = nonempty_env_or("TALOS_BUILDER_IMAGE", DEFAULT_IMAGE);

    // SECURITY: Validate container image name format to prevent injection via env var.
    // While Command::arg() uses execvp (no shell), an invalid image name could still
    // cause confusing errors or be exploited if the name is logged/templated elsewhere.
    if !image
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b".:/_-".contains(&b))
        || image.is_empty()
    {
        bail!(
            "TALOS_BUILDER_IMAGE contains invalid characters: '{}'. \
             Only alphanumeric, '.', ':', '/', '_', '-' are allowed.",
            image
        );
    }

    let memory = nonempty_env_or("TALOS_BUILDER_MEMORY", DEFAULT_MEMORY);
    let cpus = nonempty_env_or("TALOS_BUILDER_CPUS", DEFAULT_CPUS);

    // Resolve paths to absolute for container volume mounts.
    let workspace_abs = workspace
        .canonicalize()
        .with_context(|| format!("Failed to resolve workspace path: {}", workspace.display()))?;
    let registry_abs = cargo_registry_cache
        .canonicalize()
        .unwrap_or_else(|_| cargo_registry_cache.to_path_buf());
    let wit_abs = wit_dir.canonicalize().with_context(|| {
        format!(
            "Failed to resolve WIT directory path: {}",
            wit_dir.display()
        )
    })?;

    // The container mounts the workspace at /build, the registry cache at
    // /home/builder/.cargo/registry (read-only), and the WIT directory at /wit (read-only).
    // Inside the container, the Cargo.toml references wit/talos.wit relative to the
    // workspace, so we also bind the WIT dir into /build/wit as a read-only overlay.
    let workspace_mount = format!("{}:/build:rw", workspace_abs.display());
    let registry_mount = format!(
        "{}:/home/builder/.cargo/registry:ro",
        registry_abs.display()
    );
    let wit_workspace_mount = format!("{}:/build/wit:ro", wit_abs.display());

    let mut cmd = Command::new(runtime);
    cmd.args([
        "run",
        "--rm",
        // SECURITY: No network access — proc macros cannot phone home
        "--network=none",
        // SECURITY: Read-only root filesystem — no persistent writes outside mounts
        "--read-only",
        // Writable /tmp for cargo intermediate artifacts
        "--tmpfs",
        "/tmp:rw,size=1g",
        // SECURITY: Memory limit to prevent fork bombs / OOM
        "--memory",
        &memory,
        // SECURITY: CPU limit to prevent resource starvation
        "--cpus",
        &cpus,
        // SECURITY: Run as non-root user (matches builder user in Dockerfile)
        "--user",
        "1000:1000",
        // SECURITY: Drop all capabilities
        "--cap-drop=ALL",
        // SECURITY: No new privileges via setuid/setgid
        "--security-opt",
        "no-new-privileges:true",
        // Volume mounts
        "-v",
        &workspace_mount,
        "-v",
        &registry_mount,
        "-v",
        &wit_workspace_mount,
        // Working directory inside the container
        "-w",
        "/build",
        // Image
        &image,
        // The caller will append cargo subcommand args (e.g. "cargo component build ...")
        // but we need "cargo" as the entrypoint command inside the container.
        "cargo",
    ]);

    Ok(cmd)
}

/// Build a [`Command`] for running `cargo audit` inside the container.
///
/// Identical security flags as [`build_command`] including `--network=none`.
/// The RustSec advisory database is pre-fetched into the talos-builder
/// image at [`ADVISORY_DB_PATH`] (`/opt/talos-advisory-db`, see
/// `Dockerfile.builder` stage 1). The compilation service passes
/// `--db /opt/talos-advisory-db` to every `cargo audit` invocation so
/// the path is explicit, matching the controller image's identical
/// stable bake-in. If you set `TALOS_BUILDER_IMAGE` to a custom image,
/// bake the DB at the same path or every audit fails closed.
pub fn audit_command(workspace: &Path, cargo_registry_cache: &Path) -> Result<Command> {
    if !container_enabled() {
        tracing::debug!("Container compilation disabled — using direct cargo for audit");
        return Ok(Command::new("cargo"));
    }

    let runtime = match detect_runtime() {
        Some(rt) => rt,
        None => {
            // Same fail-closed-by-default policy as `build_command`: missing
            // sandbox in production = bail. Opt-in via
            // `TALOS_COMPILATION_ALLOW_HOST_FALLBACK=true` mirrors `build_command`.
            if talos_config::is_production() && !host_fallback_allowed() {
                bail!(
                    "Container compilation is required in production but neither \
                     podman nor docker was found in PATH. Install a container \
                     runtime in the controller pod, or set \
                     TALOS_COMPILATION_ALLOW_HOST_FALLBACK=acknowledge-single-tenant-rce-risk \
                     if you accept the unsandboxed fallback (single-tenant only). \
                     The short-form values (`true`/`1`/`yes`) accepted in dev are \
                     intentionally REFUSED in production to prevent accidental \
                     dev-config inheritance."
                );
            }
            if talos_config::is_production() {
                tracing::warn!(
                    target: "talos_compilation",
                    event_kind = "compilation_unsandboxed_fallback",
                    fallback_reason = "no_runtime",
                    "cargo-audit running outside container in production \
                     because TALOS_COMPILATION_ALLOW_HOST_FALLBACK=true."
                );
            } else {
                tracing::warn!("No container runtime found — falling back to direct cargo audit");
            }
            return Ok(Command::new("cargo"));
        }
    };

    let image = nonempty_env_or("TALOS_BUILDER_IMAGE", DEFAULT_IMAGE);
    if !image
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b".:/_-".contains(&b))
        || image.is_empty()
    {
        bail!(
            "TALOS_BUILDER_IMAGE contains invalid characters: '{}'",
            image
        );
    }
    let memory = nonempty_env_or("TALOS_BUILDER_MEMORY", DEFAULT_MEMORY);
    let cpus = nonempty_env_or("TALOS_BUILDER_CPUS", DEFAULT_CPUS);

    let workspace_abs = workspace
        .canonicalize()
        .with_context(|| format!("Failed to resolve workspace path: {}", workspace.display()))?;
    let registry_abs = cargo_registry_cache
        .canonicalize()
        .unwrap_or_else(|_| cargo_registry_cache.to_path_buf());

    let workspace_mount = format!("{}:/build:ro", workspace_abs.display());
    let registry_mount = format!(
        "{}:/home/builder/.cargo/registry:ro",
        registry_abs.display()
    );

    let mut cmd = Command::new(runtime);
    cmd.args([
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,size=256m",
        "--memory",
        &memory,
        "--cpus",
        &cpus,
        "--user",
        "1000:1000",
        "--cap-drop=ALL",
        "--security-opt",
        "no-new-privileges:true",
        "-v",
        &workspace_mount,
        "-v",
        &registry_mount,
        "-w",
        "/build",
        &image,
        "cargo",
    ]);

    Ok(cmd)
}

#[cfg(test)]
/// Crate-wide test serialization lock for env-var-touching tests.
///
/// `std::env::set_var` is process-global; if two tests in different
/// modules race on `TALOS_COMPILATION_CONTAINER` or
/// `TALOS_COMPILATION_ALLOW_HOST_FALLBACK` (or `RUST_ENV`), one's
/// teardown can clobber the other's setup mid-assertion. The fix is
/// not to remove env-var coupling — `host_fallback_allowed()` and
/// `container_enabled()` are env-driven by design — but to serialize
/// the tests that mutate that shared state.
///
/// Every test in this crate that calls `std::env::set_var` /
/// `remove_var` MUST acquire `TEST_ENV_LOCK` first. The lock is held
/// across the env mutations + assertions; on test failure the
/// `MutexGuard` is poisoned but the runtime recovers via
/// `lock().unwrap_or_else(PoisonError::into_inner)`-style handling
/// (see `env_lock()` helper below).
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Acquire `TEST_ENV_LOCK`, recovering from a previous test's panic.
/// Poisoned-mutex recovery is fine here — the lock guards process
/// env state, and `set_var`/`remove_var` clean up regardless of
/// whether a prior test panicked mid-assertion.
#[cfg(test)]
pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn container_disabled_returns_plain_cargo() {
        let _g = env_lock();
        // Force container off via env var
        std::env::set_var("TALOS_COMPILATION_CONTAINER", "false");
        std::env::set_var("RUST_ENV", "development");

        let ws = PathBuf::from("/tmp/test-workspace");
        let reg = PathBuf::from("/tmp/test-registry");
        let wit = PathBuf::from("/tmp/test-wit");

        let cmd = build_command(&ws, &reg, &wit).unwrap();
        // When container is disabled, the command should be plain "cargo"
        let program = format!("{:?}", cmd.as_std().get_program());
        assert!(program.contains("cargo"), "Expected cargo, got {}", program);

        // Clean up env
        std::env::remove_var("TALOS_COMPILATION_CONTAINER");
    }

    #[test]
    fn container_enabled_env_var_parsing() {
        let _g = env_lock();
        for (val, expected) in [
            ("true", true),
            ("TRUE", true),
            ("1", true),
            ("yes", true),
            ("false", false),
            ("FALSE", false),
            ("0", false),
            ("no", false),
        ] {
            std::env::set_var("TALOS_COMPILATION_CONTAINER", val);
            assert_eq!(
                container_enabled(),
                expected,
                "TALOS_COMPILATION_CONTAINER={val} should be {expected}"
            );
        }
        std::env::remove_var("TALOS_COMPILATION_CONTAINER");
    }

    #[test]
    fn host_fallback_default_off() {
        let _g = env_lock();
        std::env::remove_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK");
        assert!(
            !host_fallback_allowed(),
            "host fallback must be off by default — production missing-runtime should bail"
        );
    }

    #[test]
    fn host_fallback_recognises_truthy_values() {
        let _g = env_lock();
        for val in ["true", "TRUE", "1", "yes", "Yes"] {
            std::env::set_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK", val);
            assert!(
                host_fallback_allowed(),
                "TALOS_COMPILATION_ALLOW_HOST_FALLBACK={val} should enable fallback"
            );
        }
        std::env::remove_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK");
    }

    #[test]
    fn host_fallback_rejects_other_values() {
        let _g = env_lock();
        for val in ["false", "0", "no", "", "maybe"] {
            std::env::set_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK", val);
            assert!(
                !host_fallback_allowed(),
                "TALOS_COMPILATION_ALLOW_HOST_FALLBACK={val:?} must NOT enable fallback"
            );
        }
        std::env::remove_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK");
    }

    /// L-finding-6: in production the short-form truthy values must be
    /// REFUSED — only the explicit ack token enables fallback. Guards
    /// against an operator carrying a dev `.env` value into a prod
    /// rollout and silently running unsandboxed.
    #[test]
    fn host_fallback_prod_refuses_short_form() {
        let _g = env_lock();
        std::env::set_var("RUST_ENV", "production");
        for val in ["true", "TRUE", "1", "yes", "Yes"] {
            std::env::set_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK", val);
            assert!(
                !host_fallback_allowed(),
                "production: short-form value {val:?} MUST NOT enable fallback (ack token required)"
            );
        }
        std::env::remove_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK");
        std::env::remove_var("RUST_ENV");
    }

    /// L-finding-6: in production ONLY the explicit ack token enables
    /// the fallback. Case-insensitive match on the token; surrounding
    /// whitespace is trimmed.
    #[test]
    fn host_fallback_prod_accepts_ack_token() {
        let _g = env_lock();
        std::env::set_var("RUST_ENV", "production");
        for val in [
            "acknowledge-single-tenant-rce-risk",
            "ACKNOWLEDGE-SINGLE-TENANT-RCE-RISK",
            "  acknowledge-single-tenant-rce-risk  ",
        ] {
            std::env::set_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK", val);
            assert!(
                host_fallback_allowed(),
                "production: ack token {val:?} MUST enable fallback"
            );
        }
        std::env::remove_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK");
        std::env::remove_var("RUST_ENV");
    }

    /// L-finding-6: the ack token also works in dev so operators can
    /// mirror prod config locally for validation without having to flip
    /// between values.
    #[test]
    fn host_fallback_dev_accepts_ack_token() {
        let _g = env_lock();
        std::env::set_var("RUST_ENV", "development");
        std::env::set_var(
            "TALOS_COMPILATION_ALLOW_HOST_FALLBACK",
            "acknowledge-single-tenant-rce-risk",
        );
        assert!(
            host_fallback_allowed(),
            "dev: ack token must also enable fallback"
        );
        std::env::remove_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK");
        std::env::remove_var("RUST_ENV");
    }

    /// L-finding-6: production rejects unrelated values just like dev.
    /// Defends against e.g. `TALOS_COMPILATION_ALLOW_HOST_FALLBACK=yes-ish`
    /// pattern-matching the prefix of the ack token by accident.
    #[test]
    fn host_fallback_prod_rejects_other_values() {
        let _g = env_lock();
        std::env::set_var("RUST_ENV", "production");
        for val in [
            "false",
            "0",
            "no",
            "",
            "maybe",
            "acknowledge",
            "acknowledge-single",
            "single-tenant-rce-risk",
        ] {
            std::env::set_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK", val);
            assert!(
                !host_fallback_allowed(),
                "production: {val:?} must NOT enable fallback (only the full ack token)"
            );
        }
        std::env::remove_var("TALOS_COMPILATION_ALLOW_HOST_FALLBACK");
        std::env::remove_var("RUST_ENV");
    }
}
