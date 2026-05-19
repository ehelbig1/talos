//! Per-execution filesystem scratch sandbox.
//!
//! The engine creates a writable directory at `<sandbox_root>/<execution_id>`
//! before each run and hands it to modules that need filesystem scratch
//! space via `cap-std` (capability-based filesystem access). A
//! [`SandboxGuard`] owns the lifetime: `Drop` removes the directory
//! tree, so cleanup runs even on panic.
//!
//! Operators disable sandboxing entirely by passing `None` to
//! [`ParallelWorkflowEngine::set_sandbox_root`](crate::ParallelWorkflowEngine::set_sandbox_root)
//! — useful on read-only filesystems, locked-down containers, or
//! Windows environments without a writable `/tmp` equivalent.

use std::path::PathBuf;
use std::sync::Arc;

use uuid::Uuid;

/// Subdirectory name appended to [`std::env::temp_dir`] when forming
/// the default sandbox root. Public so consumers building their own
/// path can match the engine's naming convention without re-deriving
/// it from the platform's tmp dir.
pub const DEFAULT_SANDBOX_DIR_NAME: &str = "workflow-engine-sandboxes";

/// Resolve the platform-appropriate default sandbox root —
/// `<std::env::temp_dir()>/workflow-engine-sandboxes`.
///
/// Per-platform examples:
///
/// * Linux / macOS → `/tmp/workflow-engine-sandboxes`
/// * macOS sandboxed processes → `<NSTemporaryDirectory>/workflow-engine-sandboxes`
/// * Windows → `%TEMP%\workflow-engine-sandboxes`
///
/// Resolves once via [`std::sync::LazyLock`] so callers can hold the
/// returned reference cheaply and the temp-dir lookup never repeats.
/// Override per-engine via
/// [`ParallelWorkflowEngine::set_sandbox_root`](crate::ParallelWorkflowEngine::set_sandbox_root)
/// when you need a different location (read-only filesystem, locked-
/// down container, persistent scratch volume, etc.).
#[must_use]
pub fn default_sandbox_root() -> &'static std::path::Path {
    use std::sync::LazyLock;
    static DEFAULT: LazyLock<PathBuf> =
        LazyLock::new(|| std::env::temp_dir().join(DEFAULT_SANDBOX_DIR_NAME));
    &DEFAULT
}

/// Deprecated alias for [`default_sandbox_root`] kept as a `&str` so
/// pre-`fn` call sites continue to compile. The string is the
/// **Linux / macOS** path verbatim, which is wrong on Windows. Prefer
/// the function form, which uses [`std::env::temp_dir`] and works
/// cross-platform.
#[deprecated(
    since = "0.1.1",
    note = "use `default_sandbox_root()` — this constant is Linux/macOS-only"
)]
pub const DEFAULT_SANDBOX_ROOT: &str = "/tmp/workflow-engine-sandboxes";

/// Create a per-execution sandbox directory under `base`, rooted at
/// `base/<execution_id>`. Returns a `cap-std` `Dir` handle for
/// capability-based filesystem access from inside module dispatch,
/// plus the resolved path (the [`SandboxGuard`] needs the latter for
/// cleanup).
///
/// Uses `create_dir_all` on both the base and per-execution paths; the
/// base is a shared directory created once and reused across executions.
/// Returns a structured error string; callers log and fall back to a
/// `None` sandbox, so this function never panics.
pub(crate) fn create_execution_sandbox(
    base: &std::path::Path,
    execution_id: Uuid,
) -> Result<(Arc<cap_std::fs::Dir>, std::path::PathBuf), String> {
    std::fs::create_dir_all(base)
        .map_err(|e| format!("Failed to create sandbox base directory: {e}"))?;

    let sandbox_path = base.join(execution_id.to_string());
    std::fs::create_dir_all(&sandbox_path)
        .map_err(|e| format!("Failed to create execution sandbox directory: {e}"))?;

    let dir = cap_std::fs::Dir::open_ambient_dir(&sandbox_path, cap_std::ambient_authority())
        .map(Arc::new)
        .map_err(|e| format!("Failed to open sandbox directory with cap-std: {e}"))?;
    Ok((dir, sandbox_path))
}

/// RAII guard that removes the execution sandbox directory when
/// dropped.
///
/// Carries the full resolved path so cleanup doesn't depend on the
/// engine's `sandbox_root` still matching what it was at creation
/// time — reconfiguring the engine mid-run would otherwise strand
/// the original directory.
pub(crate) struct SandboxGuard {
    pub(crate) execution_id: Uuid,
    pub(crate) sandbox_path: std::path::PathBuf,
}

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.sandbox_path) {
            tracing::warn!(
                "Failed to cleanup execution sandbox {}: {}",
                self.execution_id,
                e
            );
        } else {
            tracing::debug!("Cleaned up execution sandbox: {}", self.execution_id);
        }
    }
}
