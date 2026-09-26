//! The ONE way a compilation-sandbox child process runs.
//!
//! Every `cargo` / `cargo audit` / `jco` / `componentize-py` spawn in this
//! crate is built by `container::{build_command, audit_command,
//! tool_command}`, which return a [`SandboxCommand`]. Its `tokio` `Command`
//! is PRIVATE, so no caller can call `.output()` / `.spawn()` on it: the only
//! way to run one is [`SandboxCommand::run`], which takes a deadline and the
//! caller's [`CompileSlot`]. The compiler enforces "every sandbox spawn is
//! bounded"; no lint is needed.
//!
//! # Why (2026-09-25)
//!
//! Until then every spawn was `tokio::time::timeout(d, cmd.output())` with no
//! `kill_on_drop`. On expiry the `output()` future was dropped, the child
//! kept running, the function returned, and the compile-semaphore permit was
//! released — while the `podman run` / `docker run` container (2 CPU / 2 GB)
//! kept running. A module whose `build.rs` or proc-macro loops forever
//! therefore held host CPU and memory indefinitely while the platform
//! believed the slot was free, and each retry started another one.
//!
//! # What `run` guarantees
//!
//! * The child is spawned with `kill_on_drop(true)`, stdin null, stdout and
//!   stderr piped. A HOST-mode child (cargo on the controller host) is the
//!   leader of its own process group, so its rustc / build-script / proc-
//!   macro descendants can be killed with it.
//! * On deadline expiry: a host child's whole process GROUP is SIGKILLed; the
//!   direct child is killed and waited (bounded); a container run is ALSO
//!   removed with `<runtime> rm -f <name>` (bounded). Only then does `run`
//!   return [`RunError::TimedOut`] — the caller's slot is still borrowed, so
//!   the permit is held until the child and the container are gone.
//! * If the `run` future is DROPPED mid-flight (the request that awaited it
//!   was cancelled), a drop guard does the same kill, and for a container
//!   starts a detached reaper thread that runs `rm -f` while holding a clone
//!   of the [`CompileSlot`] — the permit is released when the removal ends,
//!   not when the future was dropped.
//! * A host child that exits normally has its process group SIGKILLed too:
//!   a `build.rs` that backgrounds a looping process with its stdio detached
//!   would otherwise outlive a SUCCESSFUL compile, which is the same
//!   exhaustion by another door.
//! * stdout and stderr are each captured up to [`MAX_CAPTURED_STREAM_BYTES`];
//!   bytes past the cap are read and discarded (so the child never blocks on
//!   a full pipe) and one marker line is appended after the kept prefix.
//!
//! # Container mode is killed by NAME, not by process group
//!
//! A container's workload is not in the client's process group — it runs
//! under the runtime daemon (docker) or conmon (podman), which is why killing
//! the client never stopped it. The container is named
//! `talos-sandbox-<uuid-v4>` and labelled `talos.sandbox=1`, and removed by
//! name. The podman/docker CLIENT is killed by pid only: it holds nothing
//! worth killing a group for, and a rootless podman's first invocation can
//! leave a long-lived namespace "pause" process that a group kill must not
//! risk reaching.
//!
//! # Stated limits
//!
//! * A controller killed with SIGKILL (or by the OOM killer) runs no drop
//!   guard, so a running container is orphaned. `docker run` has no
//!   run-duration flag to bound it independently; the label is there so an
//!   operator can find and remove them
//!   (`<runtime> ps -a --filter label=talos.sandbox=1`).
//! * `rm -f` racing the container's CREATION can miss it (the client was
//!   killed after the create request reached the daemon but before the
//!   container existed). Such a container is created and never started — it
//!   consumes no CPU — and carries the label.
//! * On the cancel path a HOST child's slot is released once SIGKILL has been
//!   delivered to its group, not once the exit has been observed (the child
//!   is reaped by tokio's orphan queue).
//! * A host descendant that calls `setsid()` leaves the process group and is
//!   not reached by the group kill. The container envelope does not have this
//!   gap; host mode is development-only or explicitly acknowledged in
//!   production.

use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

/// Per-stream capture cap for a sandbox child's stdout and stderr (each).
///
/// Cargo's diagnostics for one `lib.rs`, a `cargo audit --json` report and
/// `--message-format=json` artifact lines for a dependency graph are all
/// well under this; a proc-macro printing in a loop for the full deadline is
/// not, and without a cap that is an unbounded host allocation.
pub const MAX_CAPTURED_STREAM_BYTES: usize = 8 * 1024 * 1024;

/// Every sandbox container is named with this prefix plus a v4 uuid.
pub const SANDBOX_CONTAINER_NAME_PREFIX: &str = "talos-sandbox-";

/// Every sandbox container carries this label, so an operator can find the
/// ones a controller crash orphaned.
pub const SANDBOX_CONTAINER_LABEL: &str = "talos.sandbox=1";

/// Upper bound on one `<runtime> rm -f <name>`.
const CONTAINER_RM_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on waiting for a SIGKILLed direct child to be reaped.
const CHILD_EXIT_GRACE: Duration = Duration::from_secs(5);

/// A held compile-concurrency permit. Cloneable: the permit returns to its
/// semaphore when the LAST clone drops, which is what lets a detached
/// container reaper keep the slot occupied until the container is gone.
#[derive(Clone, Debug)]
pub struct CompileSlot {
    _permit: Arc<OwnedSemaphorePermit>,
}

impl CompileSlot {
    /// Wait for a permit on `semaphore`. Callers bound the wait themselves
    /// (`tokio::time::timeout`) so each keeps its own queue-full message.
    pub async fn acquire(semaphore: Arc<Semaphore>) -> Result<Self, AcquireError> {
        Ok(Self {
            _permit: Arc::new(semaphore.acquire_owned().await?),
        })
    }
}

/// Why a sandbox child did not produce an [`Output`].
#[derive(Debug)]
pub enum RunError {
    /// The child ran past its deadline. It (and for a container, the
    /// container) has been killed and removed before this is returned.
    TimedOut { after: Duration },
    /// The child could not be started.
    Spawn(io::Error),
    /// Waiting for the child or reading its output failed. The child has
    /// been killed before this is returned.
    Io(io::Error),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Deliberately tokio's `Elapsed` text: the call sites used to
            // `.context(msg)` a `tokio::time::error::Elapsed`, so an
            // alternate-form render (`{:#}`) of their errors is unchanged.
            RunError::TimedOut { .. } => f.write_str("deadline has elapsed"),
            RunError::Spawn(e) => write!(f, "failed to spawn the sandbox process: {e}"),
            RunError::Io(e) => write!(f, "sandbox process I/O failed: {e}"),
        }
    }
}

impl std::error::Error for RunError {}

impl RunError {
    pub fn is_timed_out(&self) -> bool {
        matches!(self, RunError::TimedOut { .. })
    }

    /// The pre-`run` shape `tokio::time::timeout(..).await.context(msg)??`:
    /// a timeout becomes `msg` over a `deadline has elapsed` source; a spawn
    /// or I/O failure propagates as the underlying `io::Error`.
    pub fn with_timeout_context(self, msg: &'static str) -> anyhow::Error {
        match self {
            e @ RunError::TimedOut { .. } => anyhow::Error::new(e).context(msg),
            RunError::Spawn(e) | RunError::Io(e) => anyhow::Error::new(e),
        }
    }

    /// The pre-`run` shape `.map_err(|_| anyhow!(msg))??`: a timeout becomes
    /// the bare `msg`; a spawn or I/O failure propagates as the `io::Error`.
    pub fn with_timeout_message(self, msg: &'static str) -> anyhow::Error {
        match self {
            RunError::TimedOut { .. } => anyhow::anyhow!(msg),
            RunError::Spawn(e) | RunError::Io(e) => anyhow::Error::new(e),
        }
    }
}

/// Identity of a sandbox container run, used to remove it by name.
#[derive(Clone, Debug)]
struct ContainerHandle {
    /// The runtime binary (`podman` / `docker`, or a test double's path).
    runtime: String,
    /// `talos-sandbox-<uuid-v4>`, passed as `--name` to `run`.
    name: String,
}

/// A sandbox child process that has not been started. See the module docs.
#[derive(Debug)]
pub struct SandboxCommand {
    /// PRIVATE on purpose: the only way to start it is [`Self::run`].
    inner: Command,
    container: Option<ContainerHandle>,
}

impl SandboxCommand {
    /// A host-mode command. Callers pass an already-scrubbed command
    /// (`container::host_command`), never a bare `Command::new`.
    pub(crate) fn host(inner: Command) -> Self {
        Self {
            inner,
            container: None,
        }
    }

    /// `<runtime> run --name talos-sandbox-<uuid> --label talos.sandbox=1`,
    /// to which the container builders append the rest of the envelope, the
    /// image and the tool. `runtime` is a parameter (not re-detected) so
    /// tests can stand a script in for the runtime without touching `PATH`.
    pub(crate) fn container_run(runtime: &str) -> Self {
        let name = format!("{SANDBOX_CONTAINER_NAME_PREFIX}{}", Uuid::new_v4());
        let mut inner = Command::new(runtime);
        inner.args(["run", "--name", &name, "--label", SANDBOX_CONTAINER_LABEL]);
        Self {
            inner,
            container: Some(ContainerHandle {
                runtime: runtime.to_string(),
                name,
            }),
        }
    }

    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        self.inner.arg(arg);
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.inner.args(args);
        self
    }

    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.inner.current_dir(dir);
        self
    }

    pub fn env<K: AsRef<OsStr>, V: AsRef<OsStr>>(&mut self, key: K, val: V) -> &mut Self {
        self.inner.env(key, val);
        self
    }

    /// Read-only view for inspection (program, argv, env). A shared
    /// reference cannot spawn: `std::process::Command::output` needs `&mut`.
    pub fn as_std(&self) -> &std::process::Command {
        self.inner.as_std()
    }

    /// The `--name` a container run was given; `None` in host mode.
    pub fn container_name(&self) -> Option<&str> {
        self.container.as_ref().map(|c| c.name.as_str())
    }

    /// Run to completion within `deadline`, holding `slot` for the whole
    /// lifetime of the child (and of the container, if any).
    pub async fn run(self, deadline: Duration, slot: &CompileSlot) -> Result<Output, RunError> {
        self.run_capped(deadline, slot, MAX_CAPTURED_STREAM_BYTES)
            .await
    }

    async fn run_capped(
        self,
        deadline: Duration,
        slot: &CompileSlot,
        cap: usize,
    ) -> Result<Output, RunError> {
        let SandboxCommand {
            mut inner,
            container,
        } = self;
        inner
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Host mode: the child leads its own process group so the group kill
        // reaches its descendants. Container mode: the client is killed by
        // pid and the container by name (see the module docs).
        #[cfg(unix)]
        if container.is_none() {
            inner.process_group(0);
        }
        let mut child = inner.spawn().map_err(RunError::Spawn)?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let mut running = RunningChild::new(child, container, slot.clone());

        let collected = tokio::time::timeout(deadline, async {
            let (status, out, err) = tokio::join!(
                running.child.wait(),
                read_capped(stdout, cap),
                read_capped(stderr, cap),
            );
            Ok::<_, io::Error>(Output {
                status: status?,
                stdout: out?,
                stderr: err?,
            })
        })
        .await;

        match collected {
            Ok(Ok(output)) => {
                running.finish_exited();
                Ok(output)
            }
            Ok(Err(e)) => {
                running.reap("io_error").await;
                Err(RunError::Io(e))
            }
            Err(_) => {
                running.reap("deadline").await;
                Err(RunError::TimedOut { after: deadline })
            }
        }
    }
}

/// A spawned sandbox child plus everything needed to take it down. Armed
/// until the child has exited normally or been fully reaped; if it is
/// dropped while armed (the `run` future was cancelled), `Drop` kills it and
/// removes its container off-thread while holding the slot.
struct RunningChild {
    child: Child,
    /// Host mode only: the child's pid, which is also its process-group id.
    pgid: Option<i32>,
    container: Option<ContainerHandle>,
    slot: Option<CompileSlot>,
    armed: bool,
}

impl RunningChild {
    fn new(child: Child, container: Option<ContainerHandle>, slot: CompileSlot) -> Self {
        let pgid = if container.is_none() {
            child.id().and_then(|pid| i32::try_from(pid).ok())
        } else {
            None
        };
        Self {
            child,
            pgid,
            container,
            slot: Some(slot),
            armed: true,
        }
    }

    /// The child exited and both pipes reached EOF. A host child's group is
    /// killed anyway: a descendant that detached its stdio is still running.
    fn finish_exited(&mut self) {
        if let Some(pgid) = self.pgid {
            kill_process_group(pgid);
        }
        self.armed = false;
    }

    /// Kill the child (its group, for host mode), wait for it, and remove the
    /// container. Disarms only once all of that has finished, so a
    /// cancellation in the middle still reaches the drop guard.
    async fn reap(&mut self, cause: &'static str) {
        if let Some(pgid) = self.pgid {
            kill_process_group(pgid);
        }
        let _ = self.child.start_kill();
        let exited = tokio::time::timeout(CHILD_EXIT_GRACE, self.child.wait())
            .await
            .is_ok();
        if let Some(container) = &self.container {
            remove_container(container).await;
        }
        tracing::warn!(
            target: "talos_compilation",
            event_kind = "sandbox_child_killed",
            cause,
            mode = if self.container.is_some() { "container" } else { "host" },
            container = self.container.as_ref().map(|c| c.name.as_str()).unwrap_or(""),
            client_exit_observed = exited,
            "sandbox process killed before completion; its compile slot is released only now"
        );
        self.armed = false;
    }
}

impl Drop for RunningChild {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(pgid) = self.pgid {
            kill_process_group(pgid);
        }
        let _ = self.child.start_kill();
        tracing::warn!(
            target: "talos_compilation",
            event_kind = "sandbox_run_cancelled",
            mode = if self.container.is_some() { "container" } else { "host" },
            container = self.container.as_ref().map(|c| c.name.as_str()).unwrap_or(""),
            "sandbox run cancelled mid-flight; killing the child"
        );
        if let Some(container) = self.container.take() {
            spawn_detached_removal(container, self.slot.take());
        }
    }
}

/// SIGKILL every process in group `pgid`. Refuses `pgid <= 1`: `killpg(0)`
/// would kill the CONTROLLER's own group and `killpg(1)` init's.
#[cfg(unix)]
fn kill_process_group(pgid: i32) {
    if pgid <= 1 {
        return;
    }
    // SAFETY: `killpg` takes two plain integers and touches no memory owned
    // by this process; the guard above excludes the two special group ids.
    #[allow(unsafe_code)] // see SAFETY above
    let rc = unsafe { libc::killpg(pgid, libc::SIGKILL) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        // ESRCH = the group is already empty, which is the common case after
        // a normal exit.
        if err.raw_os_error() != Some(libc::ESRCH) {
            tracing::warn!(
                target: "talos_compilation",
                event_kind = "sandbox_group_kill_failed",
                pgid,
                error = %err,
                "could not SIGKILL the sandbox process group"
            );
        }
    }
}

#[cfg(not(unix))]
fn kill_process_group(_pgid: i32) {}

/// `<runtime> rm -f <name>`, bounded by [`CONTAINER_RM_TIMEOUT`].
async fn remove_container(container: &ContainerHandle) {
    let mut cmd = Command::new(&container.runtime);
    cmd.args(["rm", "-f", &container.name])
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match tokio::time::timeout(CONTAINER_RM_TIMEOUT, cmd.status()).await {
        Ok(Ok(status)) => log_removal(container, status.success(), None),
        Ok(Err(e)) => log_removal(container, false, Some(e.to_string())),
        Err(_) => log_removal(container, false, Some("rm -f timed out".to_string())),
    }
}

/// The drop-path reaper. Always a thread, never a task: a task spawned onto a
/// runtime that is shutting down is dropped unrun, which would release the
/// slot without removing the container.
fn spawn_detached_removal(container: ContainerHandle, slot: Option<CompileSlot>) {
    let for_thread = container.clone();
    // Held here until this function returns, so the inline fallback below
    // also removes the container with the slot still occupied.
    let held = slot.clone();
    let spawned = std::thread::Builder::new()
        .name("talos-sandbox-reaper".to_string())
        .spawn(move || {
            remove_container_blocking(&for_thread);
            drop(slot);
        });
    if let Err(e) = spawned {
        tracing::error!(
            target: "talos_compilation",
            event_kind = "sandbox_reaper_spawn_failed",
            container = %container.name,
            error = %e,
            "could not start the reaper thread; removing the container inline"
        );
        remove_container_blocking(&container);
    }
    drop(held);
}

fn remove_container_blocking(container: &ContainerHandle) {
    let spawned = std::process::Command::new(&container.runtime)
        .args(["rm", "-f", &container.name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => return log_removal(container, false, Some(e.to_string())),
    };
    let deadline = Instant::now() + CONTAINER_RM_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return log_removal(container, status.success(), None),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return log_removal(container, false, Some("rm -f timed out".to_string()));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return log_removal(container, false, Some(e.to_string()));
            }
        }
    }
}

fn log_removal(container: &ContainerHandle, ok: bool, error: Option<String>) {
    if ok {
        tracing::debug!(
            target: "talos_compilation",
            event_kind = "sandbox_container_removed",
            container = %container.name,
            "sandbox container removed"
        );
    } else {
        // `rm -f` of a container that already exited under `--rm` is
        // reported as a failure by docker ("No such container"); the label
        // makes any genuine survivor findable.
        tracing::warn!(
            target: "talos_compilation",
            event_kind = "sandbox_container_remove_failed",
            container = %container.name,
            error = error.as_deref().unwrap_or("non-zero exit"),
            "`rm -f` of a sandbox container did not succeed; if it is still running, \
             find it with `ps -a --filter label=talos.sandbox=1`"
        );
    }
}

/// Read `stream` to EOF keeping at most `cap` bytes. Everything past the cap
/// is read and DISCARDED (so the writer never blocks on a full pipe), and
/// one marker line is appended after the untouched prefix.
async fn read_capped<R: AsyncRead + Unpin>(stream: Option<R>, cap: usize) -> io::Result<Vec<u8>> {
    let Some(mut stream) = stream else {
        return Ok(Vec::new());
    };
    let mut kept = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    let mut discarded: u64 = 0;
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let take = cap.saturating_sub(kept.len()).min(n);
        kept.extend_from_slice(&buf[..take]);
        discarded += (n - take) as u64;
    }
    if discarded > 0 {
        kept.extend_from_slice(truncation_marker(cap, discarded).as_bytes());
    }
    Ok(kept)
}

fn truncation_marker(cap: usize, discarded: u64) -> String {
    format!("\n[talos: output truncated after {cap} bytes; {discarded} further bytes discarded]\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_slot_semaphore(permits: usize) -> Arc<Semaphore> {
        Arc::new(Semaphore::new(permits))
    }

    async fn slot() -> CompileSlot {
        CompileSlot::acquire(test_slot_semaphore(1))
            .await
            .expect("fresh semaphore")
    }

    /// A host-mode command through the production scrubbed constructor.
    fn host(program: &str) -> SandboxCommand {
        crate::container::host_command(program)
    }

    #[cfg(unix)]
    fn pid_is_gone(pid: i32) -> bool {
        // SAFETY: signal 0 performs only the existence/permission check.
        #[allow(unsafe_code)] // signal 0 only probes for existence
        let rc = unsafe { libc::kill(pid, 0) };
        rc != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }

    #[cfg(unix)]
    async fn wait_until_gone(pid: i32, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if pid_is_gone(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        pid_is_gone(pid)
    }

    async fn read_pid_file(path: &Path) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(text) = tokio::fs::read_to_string(path).await {
                if let Ok(pid) = text.trim().parse::<i32>() {
                    return pid;
                }
            }
            assert!(Instant::now() < deadline, "pid file never written");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn a_normal_child_returns_its_output() {
        let mut cmd = host("sh");
        cmd.args(["-c", "echo out; echo err >&2"]);
        let out = cmd
            .run(Duration::from_secs(10), &slot().await)
            .await
            .unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, b"out\n");
        assert_eq!(out.stderr, b"err\n");
    }

    #[tokio::test]
    async fn stdin_is_null_not_inherited() {
        // `output()` never inherited stdin; `spawn()` does by default. A
        // child reading stdin must see EOF at once, not block on ours.
        // Stated limit: this discriminates only when the test runner's own
        // stdin is live (a terminal). A runner started with stdin at
        // /dev/null (CI, most harnesses) passes with `.stdin(Stdio::null())`
        // removed — a measured survivor, so the line is guarded by review.
        let mut cmd = host("sh");
        cmd.args(["-c", "cat; echo done"]);
        let out = cmd
            .run(Duration::from_secs(10), &slot().await)
            .await
            .unwrap();
        assert_eq!(out.stdout, b"done\n");
    }

    /// The call sites' operator-facing strings are unchanged, in both the
    /// plain and the alternate (`{:#}`) render: the two helpers reproduce
    /// `timeout(..).context(msg)??` and `.map_err(|_| anyhow!(msg))??`.
    #[test]
    fn error_mapping_preserves_the_call_sites_messages() {
        let timed_out = || RunError::TimedOut {
            after: Duration::from_secs(60),
        };
        let ctx = timed_out().with_timeout_context("Compilation timed out after 60 seconds");
        assert_eq!(ctx.to_string(), "Compilation timed out after 60 seconds");
        assert_eq!(
            format!("{ctx:#}"),
            "Compilation timed out after 60 seconds: deadline has elapsed"
        );
        let bare = timed_out().with_timeout_message("JS compilation timed out after 120s");
        assert_eq!(format!("{bare:#}"), "JS compilation timed out after 120s");

        let io = || io::Error::new(io::ErrorKind::NotFound, "no such file");
        for mapped in [
            RunError::Spawn(io()).with_timeout_context("unused"),
            RunError::Io(io()).with_timeout_message("unused"),
        ] {
            assert_eq!(format!("{mapped:#}"), "no such file");
            assert!(mapped.downcast_ref::<io::Error>().is_some());
        }
    }

    #[tokio::test]
    async fn a_missing_program_is_a_spawn_error() {
        let cmd = host("talos-definitely-not-a-real-program-3f9a");
        let err = cmd
            .run(Duration::from_secs(10), &slot().await)
            .await
            .expect_err("spawn must fail");
        assert!(matches!(err, RunError::Spawn(_)), "{err:?}");
    }

    /// The process-group kill, proved on a GRANDCHILD: `sh` is the direct
    /// child; `sleep` is its child. Killing only the direct child would leave
    /// `sleep` running for a minute.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_timed_out_host_child_takes_its_descendants_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let script = format!("sleep 60 & echo $! > '{}'; wait", pid_file.display());
        let mut cmd = host("sh");
        cmd.args(["-c", &script]);

        let started = Instant::now();
        let err = cmd
            .run(Duration::from_millis(300), &slot().await)
            .await
            .expect_err("must time out");
        assert!(err.is_timed_out(), "{err:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timeout path took {:?}",
            started.elapsed()
        );

        let grandchild = read_pid_file(&pid_file).await;
        assert!(
            wait_until_gone(grandchild, Duration::from_secs(3)).await,
            "grandchild {grandchild} survived the deadline: the process group was not killed"
        );
    }

    /// The drop guard: a host run whose future is dropped mid-flight takes its
    /// whole process group down, grandchild included.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_cancelled_host_run_takes_its_descendants_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let script = format!("sleep 60 & echo $! > '{}'; wait", pid_file.display());
        let mut cmd = host("sh");
        cmd.args(["-c", &script]);
        let slot = slot().await;
        let task = tokio::spawn(async move { cmd.run(Duration::from_secs(60), &slot).await });

        let grandchild = read_pid_file(&pid_file).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(
            wait_until_gone(grandchild, Duration::from_secs(3)).await,
            "grandchild {grandchild} survived a cancelled run"
        );
    }

    /// A host child that EXITS NORMALLY after backgrounding a process with its
    /// stdio detached: the compile "succeeds", and the background process
    /// must not outlive it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_detached_descendant_does_not_outlive_a_successful_host_child() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let script = format!(
            "sleep 60 </dev/null >/dev/null 2>&1 & echo $! > '{}'",
            pid_file.display()
        );
        let mut cmd = host("sh");
        cmd.args(["-c", &script]);
        let out = cmd
            .run(Duration::from_secs(10), &slot().await)
            .await
            .unwrap();
        assert!(out.status.success());

        let grandchild = read_pid_file(&pid_file).await;
        assert!(
            wait_until_gone(grandchild, Duration::from_secs(3)).await,
            "detached grandchild {grandchild} outlived a successful run"
        );
    }

    /// Output past the cap is drained, not left in the pipe: a child writing
    /// far more than the cap to BOTH streams completes instead of blocking
    /// until the deadline, and each capture is the cap plus one marker.
    #[tokio::test]
    async fn output_past_the_cap_is_drained_and_marked() {
        let total = MAX_CAPTURED_STREAM_BYTES * 2 + 12_345;
        let script =
            format!("head -c {total} /dev/zero; head -c {total} /dev/zero >&2; echo ok >&2");
        let mut cmd = host("sh");
        cmd.args(["-c", &script]);
        let out = cmd
            .run(Duration::from_secs(30), &slot().await)
            .await
            .expect("a chatty child must complete, not block on a full pipe");
        assert!(out.status.success());
        let discarded = (total - MAX_CAPTURED_STREAM_BYTES) as u64;
        let marker = truncation_marker(MAX_CAPTURED_STREAM_BYTES, discarded);
        assert_eq!(out.stdout.len(), MAX_CAPTURED_STREAM_BYTES + marker.len());
        assert!(out.stdout[..MAX_CAPTURED_STREAM_BYTES]
            .iter()
            .all(|b| *b == 0));
        assert!(out.stdout.ends_with(marker.as_bytes()));
        assert!(out.stderr.len() <= MAX_CAPTURED_STREAM_BYTES + marker.len() + 16);
        assert!(out.stderr.ends_with(b" further bytes discarded]\n"));
    }

    #[tokio::test]
    async fn output_under_the_cap_is_untouched() {
        let mut cmd = host("sh");
        cmd.args(["-c", "head -c 5000 /dev/zero"]);
        let out = cmd
            .run_capped(Duration::from_secs(10), &slot().await, 5000)
            .await
            .unwrap();
        assert_eq!(out.stdout.len(), 5000, "exactly the cap is not truncated");
    }

    // ---- container mode, against a stand-in runtime -------------------

    /// A shell script standing in for podman/docker. `run` logs its argv and
    /// sleeps (as a container that never finishes would); `rm` sleeps 500 ms
    /// and THEN logs — so a removal that was not awaited has not logged yet
    /// when `run` returns.
    struct FakeRuntime {
        _dir: tempfile::TempDir,
        path: PathBuf,
        log: PathBuf,
    }

    impl FakeRuntime {
        async fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("fake-runtime");
            let log = dir.path().join("log");
            let script = format!(
                "#!/bin/sh\n\
                 case \"$1\" in\n\
                 probe) exit 0 ;;\n\
                 run) echo \"$*\" >> '{log}'; exec sleep 60 ;;\n\
                 rm) sleep 0.5; echo \"$*\" >> '{log}' ;;\n\
                 esac\n",
                log = log.display()
            );
            std::fs::write(&path, script).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            // Another test thread forking while the script was open for
            // writing can make the first exec fail with ETXTBSY on Linux;
            // wait until it execs cleanly before handing it out.
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match std::process::Command::new(&path).arg("probe").status() {
                    Ok(s) if s.success() => break,
                    other => {
                        assert!(
                            Instant::now() < deadline,
                            "fake runtime never ran: {other:?}"
                        );
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
            }
            Self {
                _dir: dir,
                path,
                log,
            }
        }

        fn command(&self) -> SandboxCommand {
            let mut cmd = SandboxCommand::container_run(self.path.to_str().unwrap());
            cmd.args(["--rm", "--network=none", "img:tag", "cargo", "build"]);
            cmd
        }

        fn lines(&self) -> Vec<String> {
            std::fs::read_to_string(&self.log)
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect()
        }

        fn has_line(&self, want: &str) -> bool {
            self.lines().iter().any(|l| l == want)
        }

        async fn wait_for_run_line(&self) -> String {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(l) = self.lines().into_iter().find(|l| l.starts_with("run ")) {
                    return l;
                }
                assert!(Instant::now() < deadline, "fake runtime never started");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    fn name_after_flag(run_line: &str) -> String {
        let mut words = run_line.split_whitespace();
        while let Some(w) = words.next() {
            if w == "--name" {
                return words.next().expect("--name has a value").to_string();
            }
        }
        panic!("no --name in {run_line:?}");
    }

    #[test]
    fn container_runs_are_named_and_labelled_before_the_image() {
        let cmd = SandboxCommand::container_run("podman");
        let name = cmd.container_name().unwrap().to_string();
        assert!(name.starts_with(SANDBOX_CONTAINER_NAME_PREFIX));
        let suffix = &name[SANDBOX_CONTAINER_NAME_PREFIX.len()..];
        assert_eq!(Uuid::parse_str(suffix).unwrap().get_version_num(), 4);
        let argv: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            argv,
            ["run", "--name", &name, "--label", SANDBOX_CONTAINER_LABEL]
        );
        assert!(SandboxCommand::host(tokio::process::Command::new("cargo"))
            .container_name()
            .is_none());
    }

    #[tokio::test]
    async fn a_timed_out_container_is_removed_by_name_before_run_returns() {
        let rt = FakeRuntime::new().await;
        let cmd = rt.command();
        let name = cmd.container_name().unwrap().to_string();

        let err = cmd
            .run(Duration::from_millis(500), &slot().await)
            .await
            .expect_err("must time out");
        assert!(err.is_timed_out(), "{err:?}");

        // Read the log BEFORE anything else: the removal must already have
        // happened (the stand-in's `rm` logs only after sleeping 500 ms).
        let lines = rt.lines();
        let run_line = lines
            .iter()
            .find(|l| l.starts_with("run "))
            .expect("the run was logged");
        assert_eq!(name_after_flag(run_line), name);
        assert!(
            rt.has_line(&format!("rm -f {name}")),
            "`rm -f {name}` was not run before `run` returned: {lines:?}"
        );
    }

    /// The property that matters on the cancel path: dropping the `run`
    /// future does not free the slot while the container may still be
    /// running. The permit stays taken until `rm -f` has finished.
    #[tokio::test]
    async fn a_cancelled_container_run_holds_the_slot_until_removed() {
        let rt = FakeRuntime::new().await;
        let cmd = rt.command();
        let name = cmd.container_name().unwrap().to_string();
        let sem = test_slot_semaphore(1);
        let task_sem = Arc::clone(&sem);
        let task = tokio::spawn(async move {
            let slot = CompileSlot::acquire(task_sem).await.unwrap();
            cmd.run(Duration::from_secs(60), &slot).await
        });

        rt.wait_for_run_line().await;
        assert_eq!(sem.available_permits(), 0);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        let want = format!("rm -f {name}");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !rt.has_line(&want) {
            assert_eq!(
                sem.available_permits(),
                0,
                "the slot was released before the container was removed"
            );
            assert!(Instant::now() < deadline, "the reaper never ran `{want}`");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while sem.available_permits() != 1 {
            assert!(Instant::now() < deadline, "the slot was never released");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// A real container runtime, end to end: a container that would run for
    /// five minutes is gone after a one-second deadline.
    #[tokio::test]
    #[ignore = "needs a running docker daemon and the alpine:3 image; run with --ignored"]
    async fn a_real_docker_container_is_removed_on_timeout() {
        let mut cmd = SandboxCommand::container_run("docker");
        cmd.args(["--rm", "alpine:3", "sleep", "300"]);
        let name = cmd.container_name().unwrap().to_string();
        let err = cmd
            .run(Duration::from_secs(3), &slot().await)
            .await
            .expect_err("must time out");
        assert!(err.is_timed_out());
        let ps = std::process::Command::new("docker")
            .args(["ps", "-a", "-q", "--filter", &format!("name={name}")])
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&ps.stdout).trim().is_empty(),
            "container {name} survived its deadline"
        );
    }
}
