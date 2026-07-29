#!/usr/bin/env bash
# `make up` disk preflight — refuse to start the stack onto a full Docker VM.
#
# WHY THIS EXISTS (2026-07-29 incident, second in one week):
#   The Docker VM's data disk filled during a controller rebuild. Postgres was
#   mid-checkpoint when the write failed, and Postgres's response to ENOSPC in
#   a checkpoint is a PANIC — it aborts the backend and restarts recovery,
#   which needs to write, which fails, which PANICs. The container crash-looped
#   and took the whole stack down. Nothing in the failure text says "disk":
#   the visible symptoms are Redis AOF write errors, "pool timed out" from the
#   controller, and an unhealthy postgres, which is a confused debugging
#   session every single time (the 2026-07-24 wedged-VM incident was the same
#   root cause wearing different symptoms).
#
#   Failing LOUD here, before `docker compose build`, costs a second and an
#   obvious message. Discovering it after compose has started writing costs a
#   corrupted checkpoint and an hour. So this check runs first.
#
# CONTRACT (all four matter — see the tests in the `make up` report):
#   * ADVISORY BY DEFAULT. Anything unexpected — docker not installed, daemon
#     unreachable, daemon WEDGED (accepts the connection, never answers — the
#     state a full disk actually produces), probe image absent, probe times
#     out, df output we cannot parse — SKIPS SILENTLY with exit 0. A preflight
#     that breaks `make up` on a machine with a slightly different docker is
#     worse than no preflight, and one that HANGS `make up` is worse still.
#   * >=80% used: warn, name the exact reclaim commands, exit 0.
#   * >=95% used: FAIL (exit 1), same commands, and print the override.
#   * Override: TALOS_UP_SKIP_DISK_CHECK=1 skips the whole check.
#   * Budget: ~0.3s in the healthy case. EVERY docker call runs behind the same
#     hard deadline, so the pathological case is bounded at 2 × DEADLINE_TENTHS
#     (~2s) rather than unbounded.
#
# Deliberately NOT suggested as a remedy: `docker volume prune` / `system
# prune --volumes`. Those delete the Postgres data volume — the exact data the
# check exists to protect.

set -uo pipefail

# Explicit opt-out, honored before anything else runs.
if [ "${TALOS_UP_SKIP_DISK_CHECK:-}" = "1" ]; then
  exit 0
fi

WARN_PCT="${TALOS_UP_DISK_WARN_PCT:-80}"
FAIL_PCT="${TALOS_UP_DISK_FAIL_PCT:-95}"
# The probe image. Any image with a `df` will do; alpine is already present on
# every machine that has built this stack.
PROBE_IMAGE="${TALOS_UP_DISK_PROBE_IMAGE:-alpine}"
# Hard deadline for EACH docker call, in tenths of a second. There are two
# (inspect, then run), so the pathological worst case is twice this.
DEADLINE_TENTHS="${TALOS_UP_DISK_DEADLINE_TENTHS:-10}"

YEL=$'\033[1;33m'; RED=$'\033[1;31m'; DIM=$'\033[2m'; RST=$'\033[0m'

# Everything below is best-effort. Any failure path returns 0.
command -v docker >/dev/null 2>&1 || exit 0

# `mktemp` portably: BSD (macOS) accepts `-t PREFIX` and appends its own X's,
# but GNU coreutils REJECTS a template with no X's ("too few X's in template"),
# which would have made this whole preflight a permanent silent no-op on every
# Linux dev machine. An explicit `.XXXXXX` template is the one form both
# implementations accept.
probe_out="$(mktemp "${TMPDIR:-/tmp}/talos-disk-preflight.XXXXXX" 2>/dev/null)" || exit 0
# shellcheck disable=SC2064  # expand $probe_out now, not at trap time
trap "rm -f '$probe_out'" EXIT

# Run a docker command behind a hard deadline, writing stdout to $probe_out.
#
# EVERY docker call needs this, not just the probe: a WEDGED daemon accepts the
# connection and never answers, so `docker image inspect` hangs as readily as
# `docker run` does — and a wedged daemon is precisely the state a full disk
# produces (the 2026-07-24 incident). An unguarded call there would hang
# `make up` forever, which is a far worse outcome than the corrupted checkpoint
# this script exists to prevent.
run_with_deadline() { # $@ = docker args
  : >"$probe_out"
  docker "$@" >"$probe_out" 2>/dev/null &
  local pid=$! waited=0
  while [ "$waited" -lt "$DEADLINE_TENTHS" ]; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
    waited=$((waited + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    # Wedged daemon or a very cold image layer. Not our problem to diagnose —
    # kill the call and get out of the way.
    kill -9 "$pid" >/dev/null 2>&1
    wait "$pid" 2>/dev/null
    return 1
  fi
  wait "$pid"
}

# Daemon reachable? `docker image inspect` talks to the daemon, so this doubles
# as the daemon check and the image-present check in one round trip. A missing
# image (fresh machine, pruned cache) is a SKIP, never a pull: pulling would
# blow the time budget and would be a surprising side effect of `make up`.
run_with_deadline image inspect "$PROBE_IMAGE" || exit 0

# `--pull=never` is belt to the inspect check's suspenders: even if the image
# vanished between the two calls, we fail rather than silently pulling.
# The container's `/` is the Docker VM's data disk, which is the thing that
# fills — NOT the host filesystem `df /` would report on a Mac.
run_with_deadline run --rm --pull=never "$PROBE_IMAGE" df -P / || exit 0

# Defensive parse. `df -P` promises one unwrapped line per filesystem with the
# mount point last, but we never trust that: find the line whose LAST field is
# `/`, then take the field that looks like a percentage. No eval, no field-
# position assumption, and a non-numeric or out-of-range result is a SKIP.
used_pct="$(
  awk '
    $NF == "/" {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^[0-9]+%$/) { sub(/%$/, "", $i); print $i; exit }
      }
    }
  ' "$probe_out" 2>/dev/null
)"

case "$used_pct" in
  ''|*[!0-9]*) exit 0 ;;   # empty or non-numeric — unparseable, skip
esac
[ "$used_pct" -le 100 ] 2>/dev/null || exit 0

remedies() {
  printf '%s  reclaim, in this order (none of these touch your data volumes):%s\n' "$DIM" "$RST"
  printf '%s    docker builder prune -f --keep-storage 20GB%s\n' "$DIM" "$RST"
  printf '%s    docker image prune -f%s\n' "$DIM" "$RST"
  printf '%s    docker builder prune -f --filter type=exec.cachemount   # last resort: full rebuild next time%s\n' "$DIM" "$RST"
  printf '%s  do NOT run `docker volume prune` / `system prune --volumes` — that deletes the Postgres data volume.%s\n' "$DIM" "$RST"
}

if [ "$used_pct" -ge "$FAIL_PCT" ]; then
  printf '%s✗ Docker VM disk is %s%% full (>= %s%%) — refusing to start the stack.%s\n' \
    "$RED" "$used_pct" "$FAIL_PCT" "$RST"
  printf '%s  Postgres PANICs on ENOSPC mid-checkpoint and then crash-loops in recovery;%s\n' "$RED" "$RST"
  printf '%s  the symptoms look like Redis/DB-pool errors, not like a full disk.%s\n' "$RED" "$RST"
  remedies
  printf '%s  override (you accept the risk): TALOS_UP_SKIP_DISK_CHECK=1 make up%s\n' "$DIM" "$RST"
  exit 1
fi

if [ "$used_pct" -ge "$WARN_PCT" ]; then
  printf '%s⚠ Docker VM disk is %s%% full (>= %s%%) — a rebuild may fill it.%s\n' \
    "$YEL" "$used_pct" "$WARN_PCT" "$RST"
  printf '%s  At 100%% Postgres PANICs mid-checkpoint and crash-loops. `make up` continues.%s\n' "$YEL" "$RST"
  remedies
fi

exit 0
