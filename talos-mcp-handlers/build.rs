//! Capture git state at compile time so `session_start.server_version`
//! reflects the actual code running, not just the manually-bumped
//! `Cargo.toml` version. Operators get a unique signature per rebuild.
//!
//! Surfaces three env vars to the binary:
//!   - `GIT_SHA`   — short SHA (7 chars) or "unknown" outside a git checkout
//!   - `GIT_DIRTY` — "true" or "false"; "true" when the working tree has
//!     uncommitted changes (modified files or untracked-but-tracked files).
//!     "false" outside a git checkout.
//!   - `BUILD_TIME` — RFC3339 timestamp of the build (UTC), useful for
//!     distinguishing rebuilds from the same commit.
//!
//! Re-runs whenever the git HEAD or index changes (no stale SHA cached).
//! Docker builds without .git context still succeed — we fall back to
//! "unknown" rather than failing the build.

use std::process::Command;

fn main() {
    // Re-run when git state changes. The .git/HEAD file moves on every
    // checkout / commit / branch switch; .git/index moves on every
    // `git add`. Watching both covers the staleness window.
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/index");
    // BUILD_TIME should change every build — easiest signal is to invalidate
    // the build script unconditionally on a known-changing env var. Cargo
    // re-runs build.rs when ANY rerun-if-* changes, so adding the source
    // of `BUILD_TIME` (always-different) guarantees freshness.
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    // Prefer build-arg env vars (set by docker-compose.yml + Dockerfile so
    // Docker builds, which exclude .git from context, still get a real SHA).
    // Fall back to invoking git directly when running outside Docker.
    let sha = std::env::var("GIT_SHA_OVERRIDE")
        .ok()
        .filter(|s| !s.is_empty() && s != "unknown")
        .or_else(|| git("rev-parse --short=7 HEAD"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let dirty = std::env::var("GIT_DIRTY_OVERRIDE").ok().unwrap_or_else(|| {
        match git("status --porcelain") {
            Some(output) if !output.is_empty() => "true".to_string(),
            Some(_) => "false".to_string(),
            None => "false".to_string(),
        }
    });
    println!("cargo:rerun-if-env-changed=GIT_SHA_OVERRIDE");
    println!("cargo:rerun-if-env-changed=GIT_DIRTY_OVERRIDE");

    let build_time = chrono_now();

    println!("cargo:rustc-env=GIT_SHA={sha}");
    println!("cargo:rustc-env=GIT_DIRTY={dirty}");
    println!("cargo:rustc-env=BUILD_TIME={build_time}");
}

fn git(args: &str) -> Option<String> {
    let parts: Vec<&str> = args.split_whitespace().collect();
    let out = Command::new("git").args(parts).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// RFC3339 UTC timestamp. We avoid pulling chrono into build-deps —
/// hand-format from SystemTime to keep the build dep tree minimal.
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Convert epoch seconds to a human-readable timestamp (UTC).
    // Days since 1970-01-01 → year/month/day. Hours/minutes/seconds
    // from the per-day remainder.
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let h = rem / 3_600;
    let m = (rem % 3_600) / 60;
    let s = rem % 60;
    let (y, mo, d) = days_to_ymd(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Civil-date conversion borrowed from Howard Hinnant's algorithm
/// (http://howardhinnant.github.io/date_algorithms.html#civil_from_days).
/// MIT-licensed, depended-on by the C++ standard library, well-known
/// correct.
fn days_to_ymd(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
