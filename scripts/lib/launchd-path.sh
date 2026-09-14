# shellcheck shell=bash
# PATH for a launchd job, derived from where the INSTALLING shell finds the
# tools the job runs — never a hardcoded list.
#
# Why this exists (2026-09-14): scripts/drills/schedule.sh and
# scripts/offhost-backup/schedule.sh both wrote
#   PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin
# into their LaunchAgent. rustup installs `cargo` in ~/.cargo/bin — the
# DEFAULT location, not an unusual one — so the first scheduled drill ever run
# on this host died at step 2/8 with `env: cargo: No such file or directory`
# after resolving the escrowed key correctly. Both jobs `cargo build` before
# doing anything, so both were broken the same way, and `status` still said
# "✓ scheduled" because it only checked that the plist existed.
#
# Sourced by both schedulers; tested by scripts/tests/launchd-path-test.sh
# (pure bash, runs in CI and on a laptop).

# Directories every launchd job gets regardless of what was resolved, so a
# tool the job reaches only indirectly (e.g. `security`, `python3`) keeps
# working exactly as it did before this helper existed.
LAUNCHD_BASE_PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"

# launchd_path_for TOOL... — print a PATH on which every TOOL resolves: the
# directory of each tool as THIS shell resolves it (in argument order), then
# LAUNCHD_BASE_PATH, with duplicates removed. `type -P` so an alias or a shell
# function never counts as a tool the job can execute.
#
# Returns 1 (printing nothing on stdout) if any TOOL does not resolve, naming
# every missing tool on stderr — a scheduled job that cannot find its first
# command must be refused at install time, not discovered at 03:00.
launchd_path_for() {
    local tool resolved dir missing=() dirs=()
    for tool in "$@"; do
        resolved="$(type -P "$tool" 2>/dev/null || true)"
        if [[ -z "$resolved" ]]; then
            missing+=("$tool")
            continue
        fi
        dir="$(dirname "$resolved")"
        dirs+=("$dir")
    done
    if ((${#missing[@]} > 0)); then
        printf 'launchd PATH: not found on this shell'\''s PATH: %s\n' "${missing[*]}" >&2
        return 1
    fi
    local out="" seen=":" part
    local IFS=:
    # shellcheck disable=SC2206 # splitting the base PATH on ':' is the point
    local base=($LAUNCHD_BASE_PATH)
    # `${dirs[@]+…}`: macOS's /bin/bash is 3.2, where expanding an EMPTY array
    # under `set -u` is an "unbound variable" abort (both schedulers run
    # `set -u`), and inside an `if` that abort exits the whole shell with 0.
    for part in ${dirs[@]+"${dirs[@]}"} "${base[@]}"; do
        [[ -n "$part" ]] || continue
        case "$seen" in *":$part:"*) continue ;; esac
        seen="$seen$part:"
        out="${out:+$out:}$part"
    done
    printf '%s\n' "$out"
}

# launchd_path_missing PATH TOOL... — print (one per line) each TOOL that does
# NOT resolve on PATH. Used by `status` to check an INSTALLED plist, so a
# schedule written before this fix — or after a tool moved — reports broken
# instead of "✓ scheduled".
launchd_path_missing() {
    local path="$1" tool
    shift
    for tool in "$@"; do
        if [[ -z "$(PATH="$path" type -P "$tool" 2>/dev/null || true)" ]]; then
            printf '%s\n' "$tool"
        fi
    done
}
