//! Process posture shared by the controller and the worker binaries.
//!
//! Both processes hold secret material in memory: the controller its
//! environment (`TALOS_MASTER_KEY`, `WORKER_SHARED_KEY`, `JWT_SECRET`), the
//! worker every in-flight job's opened secret map and its fleet key. Marking
//! the process non-dumpable closes the two cheap recovery paths a same-UID
//! neighbour has — a core dump and `ptrace` attach — and makes the `/proc`
//! entries root-owned so `/proc/<pid>/environ` cannot be read by a child or a
//! sibling of the same user.
//!
//! Until 2026-10-15 only the controller did this (a private function in its
//! `main.rs`, written for the host-compile fallback that let a user module's
//! `build.rs` run as the controller's UID). The worker, which holds the
//! plaintext of every job it runs, did not (security review 2026-10-15,
//! worker-side residency). ONE home now; both binaries call it first thing.

/// `prctl(PR_SET_DUMPABLE, 0)` on Linux.
///
/// Side effects, accepted: no core dumps, and a same-UID debugger cannot
/// ptrace-attach (use root / `CAP_SYS_PTRACE`). The process still reads its
/// own `/proc/self`. `execve` resets the flag, so compiler children the
/// controller spawns are unaffected. Returns `Ok(())` off Linux, where there is
/// no `/proc/<pid>/environ` to protect.
///
/// # Errors
/// The OS error text when the call fails. A caller logs it and continues: the
/// posture is defence in depth, not a precondition (operator decision G-9,
/// 2026-10-15, retired the one configuration in which a failure refused boot).
pub fn make_process_non_dumpable() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        extern "C" {
            fn prctl(option: std::ffi::c_int, ...) -> std::ffi::c_int;
        }
        const PR_SET_DUMPABLE: std::ffi::c_int = 4;
        // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes one integer argument and
        // touches no caller memory.
        #[allow(unsafe_code)] // see SAFETY above.
        let rc = unsafe { prctl(PR_SET_DUMPABLE, 0 as std::ffi::c_ulong) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    Ok(())
}

/// Log the outcome of [`make_process_non_dumpable`] once tracing is up. The
/// call itself runs before any subscriber exists (the environment must be
/// protected before anything else reads it), so the two halves are separate.
pub fn log_non_dumpable_outcome(result: &Result<(), String>) {
    match result {
        Ok(()) => tracing::info!("process marked non-dumpable (PR_SET_DUMPABLE=0)"),
        Err(e) => tracing::warn!(error = %e, "could not mark the process non-dumpable"),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    #[allow(unsafe_code)] // prctl(PR_GET_DUMPABLE) FFI read.
    fn the_process_is_non_dumpable_afterwards() {
        extern "C" {
            fn prctl(option: std::ffi::c_int, ...) -> std::ffi::c_int;
        }
        const PR_GET_DUMPABLE: std::ffi::c_int = 3;
        make_process_non_dumpable().expect("prctl");
        // SAFETY: PR_GET_DUMPABLE takes no further arguments.
        assert_eq!(unsafe { prctl(PR_GET_DUMPABLE) }, 0);
    }
}
