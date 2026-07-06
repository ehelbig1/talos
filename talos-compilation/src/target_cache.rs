//! Per-user persistent `CARGO_TARGET_DIR` cache for runtime WASM compiles.
//!
//! Every `compile_to_wasm*` call builds in a fresh throwaway workspace, so
//! without a persistent target dir cargo recompiles the entire dependency
//! graph (serde, chrono, wit-bindgen, …) on every call — the dominant cost
//! of the 15-30 s compile cycle. Dependencies are identical across compiles
//! (fixed allowlist + read-only registry snapshot), so a persistent target
//! dir turns the second and later compiles into "recompile the user's
//! lib.rs only" (~2-3 s).
//!
//! # Security invariant: the cache is scoped PER USER, never shared
//!
//! The build sandbox runs user-supplied Rust (proc-macros execute at build
//! time) with the target dir mounted read-write. Cargo's fingerprint
//! checks are freshness checks, not integrity checks — a hostile build can
//! overwrite any cached `.rlib`/`.rmeta` in the mounted dir, and a later
//! build that trusts those artifacts links the poisoned bytes into its
//! WASM. A fleet-shared cache would therefore let tenant A inject code
//! into tenant B's modules. Keying the cache by the requesting `user_id`
//! bounds poisoning to the attacker's own modules — exactly the trust they
//! already have over their own source. Do not "optimise" this into a
//! shared cache.
//!
//! # Layout, lifecycle
//!
//! `{root}/{user_id}/` — root defaults to `/tmp/cargo-target/per-user`
//! (under the same mount the controller image already persists across
//! container restarts in compose; pod-lifetime tmpfs on k8s). Each use
//! touches `{dir}/.last_used`; a rate-limited opportunistic sweep removes
//! user dirs idle past the TTL so the cache can't grow with
//! distinct-users-ever-seen (the keyed-cache sweep rule).
//!
//! Env knobs:
//! * `TALOS_COMPILE_TARGET_CACHE` — `0|false|no|off` disables (default on).
//! * `TALOS_COMPILE_TARGET_CACHE_DIR` — cache root override.
//! * `TALOS_COMPILE_TARGET_CACHE_TTL_HOURS` — idle eviction TTL
//!   (default 168 = 7 days; `0` = never sweep).

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use uuid::Uuid;

const DEFAULT_ROOT: &str = "/tmp/cargo-target/per-user";
const DEFAULT_TTL_HOURS: u64 = 168;
const LAST_USED_MARKER: &str = ".last_used";
/// Minimum interval between sweep passes. The sweep is O(number of user
/// dirs) of `readdir` + stat — cheap, but there is no reason to run it on
/// every compile.
const SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

/// Pure parse of the enable flag: `None` (unset) and anything not in the
/// explicit off-list is ON. Mirrors the repo's opt-OUT flag convention.
fn parse_enabled(value: Option<&str>) -> bool {
    match value {
        Some(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "0" | "false" | "no" | "off")
        }
        None => true,
    }
}

fn cache_enabled() -> bool {
    parse_enabled(std::env::var("TALOS_COMPILE_TARGET_CACHE").ok().as_deref())
}

fn cache_root() -> PathBuf {
    match std::env::var("TALOS_COMPILE_TARGET_CACHE_DIR") {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v.trim()),
        _ => PathBuf::from(DEFAULT_ROOT),
    }
}

/// Idle TTL before a user's cache dir is swept. `0` disables sweeping.
fn ttl() -> Duration {
    let hours = std::env::var("TALOS_COMPILE_TARGET_CACHE_TTL_HOURS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_TTL_HOURS);
    Duration::from_secs(hours.saturating_mul(3600))
}

/// The per-user cache dir. `user_id` is a `Uuid`, so the path component is
/// structurally safe (no separators, no traversal).
fn user_cache_dir(root: &Path, user_id: Uuid) -> PathBuf {
    root.join(user_id.to_string())
}

/// Resolve (and create) the persistent target dir for this user's compile.
/// Returns `None` when the cache is disabled or the dir can't be created —
/// callers fall back to the legacy throwaway `{workspace}/target`, so a
/// cache-infrastructure problem degrades to slow, never to broken.
pub(crate) fn resolve_for(user_id: Uuid) -> Option<PathBuf> {
    if !cache_enabled() {
        return None;
    }
    let root = cache_root();
    let dir = user_cache_dir(&root, user_id);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!(
            target: "talos_compilation",
            event_kind = "target_cache_unavailable",
            error = %e,
            dir = %dir.display(),
            "could not create per-user target cache dir — compiling cold"
        );
        return None;
    }
    // Touch the marker so the sweep sees this user as active. Recreating
    // the file updates its mtime; failure only risks early eviction.
    let _ = std::fs::write(dir.join(LAST_USED_MARKER), b"");
    maybe_sweep(&root);
    Some(dir)
}

/// Rate-limited opportunistic sweep (at most one pass per
/// [`SWEEP_INTERVAL`] per process; concurrent compiles skip via
/// `try_lock` instead of queueing).
fn maybe_sweep(root: &Path) {
    use std::sync::{Mutex, OnceLock};
    static LAST_SWEEP: OnceLock<Mutex<Option<std::time::Instant>>> = OnceLock::new();
    let last = LAST_SWEEP.get_or_init(|| Mutex::new(None));
    let Ok(mut guard) = last.try_lock() else {
        return;
    };
    if guard.map(|t| t.elapsed() < SWEEP_INTERVAL).unwrap_or(false) {
        return;
    }
    *guard = Some(std::time::Instant::now());
    let ttl = ttl();
    if ttl.is_zero() {
        return;
    }
    let removed = sweep_stale(root, ttl, SystemTime::now());
    if removed > 0 {
        tracing::info!(
            target: "talos_compilation",
            event_kind = "target_cache_swept",
            removed,
            "evicted idle per-user compile target caches"
        );
    }
}

/// Remove user cache dirs whose `.last_used` marker (dir mtime as
/// fallback) is older than `ttl` relative to `now`. Split out with `now`
/// as a parameter so eviction logic is unit-testable without mutating
/// filesystem timestamps.
fn sweep_stale(root: &Path, ttl: Duration, now: SystemTime) -> usize {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let last_used = std::fs::metadata(path.join(LAST_USED_MARKER))
            .and_then(|m| m.modified())
            .or_else(|_| std::fs::metadata(&path).and_then(|m| m.modified()));
        let stale = match last_used {
            Ok(t) => now.duration_since(t).map(|age| age > ttl).unwrap_or(false),
            // Unreadable metadata: leave it alone rather than guess.
            Err(_) => false,
        };
        if stale && std::fs::remove_dir_all(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_by_default_and_off_list_disables() {
        assert!(parse_enabled(None));
        assert!(parse_enabled(Some("1")));
        assert!(parse_enabled(Some("true")));
        assert!(parse_enabled(Some("anything-else")));
        for off in ["0", "false", "no", "off", " OFF ", "False"] {
            assert!(!parse_enabled(Some(off)), "{off:?} should disable");
        }
    }

    #[test]
    fn user_dir_is_uuid_keyed_under_root() {
        let id = Uuid::nil();
        let dir = user_cache_dir(Path::new("/cache"), id);
        assert_eq!(
            dir,
            PathBuf::from("/cache/00000000-0000-0000-0000-000000000000")
        );
    }

    #[test]
    fn sweep_removes_only_dirs_past_ttl() {
        let root = tempfile::tempdir().expect("tempdir");
        let stale = root.path().join(Uuid::new_v4().to_string());
        let fresh = root.path().join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::create_dir_all(&fresh).unwrap();
        std::fs::write(stale.join(LAST_USED_MARKER), b"").unwrap();
        std::fs::write(fresh.join(LAST_USED_MARKER), b"").unwrap();

        let ttl = Duration::from_secs(3600);
        // "now" far in the future relative to the markers just written →
        // both are stale; "now" = now → neither is.
        assert_eq!(sweep_stale(root.path(), ttl, SystemTime::now()), 0);
        assert!(stale.exists() && fresh.exists());

        let future = SystemTime::now() + ttl + Duration::from_secs(60);
        // Give one dir a fresh marker relative to `future` by rewriting it
        // is impossible without mtime control — instead assert the
        // all-stale case, which pins the removal path.
        assert_eq!(sweep_stale(root.path(), ttl, future), 2);
        assert!(!stale.exists() && !fresh.exists());
    }

    #[test]
    fn sweep_ignores_plain_files_in_root() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::write(root.path().join("stray-file"), b"x").unwrap();
        let future = SystemTime::now() + Duration::from_secs(999_999);
        assert_eq!(sweep_stale(root.path(), Duration::from_secs(1), future), 0);
        assert!(root.path().join("stray-file").exists());
    }
}
