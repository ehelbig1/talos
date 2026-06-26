#!/usr/bin/env bash
# `make doctor` — preflight diagnosis of the recurring local-dev failure
# modes this repo keeps hitting:
#
#   1. A controller/worker image gone STALE vs your working tree — you edit
#      Rust, forget to rebuild, and `make up`'s cached image live-tests OLD
#      code. This is the documented `live_testing_gotchas` trap; it has cost
#      real debugging time because nothing surfaces it.
#   2. Docker-VM disk pressure — repeated ~3GB controller rebuilds fill the
#      Docker VM disk, which manifests as unrelated-looking failures (Redis
#      AOF write errors, "pool timed out" DB errors) rather than an obvious
#      ENOSPC. Catching it early saves a confused debugging session.
#   3. A half-up stack (a core service crashed/unhealthy) before you waste a
#      live test on it.
#
# ADVISORY: always exits 0. It prints ✓ / ⚠ / ✗ per check with the exact fix
# command, so it's safe to run any time (and before every live test).

set -uo pipefail
cd "$(dirname "$0")/.." || exit 0

GREEN=$'\033[1;32m'; YEL=$'\033[1;33m'; RED=$'\033[1;31m'; DIM=$'\033[2m'; RST=$'\033[0m'
ISSUES=0
pass() { printf '  %s✓%s %s\n' "$GREEN" "$RST" "$1"; }
warn() { printf '  %s⚠%s %s\n' "$YEL" "$RST" "$1"; ISSUES=$((ISSUES+1)); }
bad()  { printf '  %s✗%s %s\n' "$RED" "$RST" "$1"; ISSUES=$((ISSUES+1)); }
hint() { printf '      %s↳ %s%s\n' "$DIM" "$1" "$RST"; }

# Disk-pressure threshold: warn when reclaimable build cache + the Docker
# data root get large. The exact VM disk % isn't portable to read, so we use
# build-cache size as the actionable proxy — `docker builder prune` is the fix.
BUILD_CACHE_WARN_GB="${TALOS_DOCTOR_BUILD_CACHE_WARN_GB:-8}"

printf '%sTalos local-dev doctor%s\n' "$GREEN" "$RST"

# ── 1. Docker daemon ────────────────────────────────────────────────────
printf '\nDocker\n'
if ! docker info >/dev/null 2>&1; then
  bad "Docker daemon not reachable"
  hint "start Docker Desktop / the docker service, then re-run make doctor"
  printf '\n%s%d issue(s).%s Docker is required for the rest of the checks.\n' "$RED" "$ISSUES" "$RST"
  exit 0
fi
pass "daemon reachable"

# ── 2. Docker disk pressure ─────────────────────────────────────────────
# Parse `docker system df` for the Build Cache size. Format is human (e.g.
# "4.965GB"); normalize to GB for the threshold compare.
df_line=$(docker system df 2>/dev/null | awk '/^Build Cache/{print $0}')
cache_size=$(printf '%s' "$df_line" | awk '{for(i=1;i<=NF;i++) if($i ~ /(GB|MB|kB|B)$/){print $i; exit}}')
cache_gb=$(python3 - "$cache_size" <<'PY' 2>/dev/null || echo 0
import sys,re
s=(sys.argv[1] if len(sys.argv)>1 else "0B").strip()
m=re.match(r'([0-9.]+)\s*([kKMGT]?i?B)', s)
if not m: print("0"); raise SystemExit
v=float(m.group(1)); u=m.group(2).lower()
mult={'b':1e-9,'kb':1e-6,'mb':1e-3,'gb':1,'tb':1000,'gib':1.0737,'mib':1.0737e-3,'kib':1.0737e-6,'tib':1073.7}
print(f"{v*mult.get(u,1):.2f}")
PY
)
if awk "BEGIN{exit !($cache_gb+0 >= $BUILD_CACHE_WARN_GB)}" 2>/dev/null; then
  warn "Docker build cache is large (${cache_size:-?}) — VM disk can fill, surfacing as Redis AOF / DB pool errors"
  hint "reclaim with: docker builder prune -f   (and: docker image prune -f)"
else
  pass "build cache ${cache_size:-?} (threshold ${BUILD_CACHE_WARN_GB}GB)"
fi

# ── 3. Core services up + controller health ─────────────────────────────
printf '\nStack\n'
CORE_SERVICES="postgres redis nats controller worker"
any_running=0
for svc in $CORE_SERVICES; do
  cid=$(docker compose ps -q "$svc" 2>/dev/null)
  if [ -z "$cid" ]; then
    warn "$svc: not running"
    continue
  fi
  any_running=1
  state=$(docker inspect "$cid" --format '{{.State.Status}}' 2>/dev/null)
  health=$(docker inspect "$cid" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null)
  if [ "$state" = "running" ] && { [ "$health" = "healthy" ] || [ "$health" = "none" ]; }; then
    pass "$svc: $state${health:+ ($health)}"
  else
    bad "$svc: $state${health:+ ($health)}"
    hint "make logs SERVICE=$svc"
  fi
done
if [ "$any_running" = "0" ]; then
  warn "stack is not running"
  hint "start it with: make up"
fi

# Controller /health endpoint (the user-facing combined check).
if [ -n "$(docker compose ps -q controller 2>/dev/null)" ]; then
  if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
    pass "controller /health responds (http://localhost:8000/health)"
  else
    bad "controller /health not responding"
    hint "make logs SERVICE=controller   (it may still be booting)"
  fi
fi

# ── 4. Image staleness vs working tree (the headline check) ─────────────
# Compare each service image's build time against the newest git-tracked
# build input (*.rs / Cargo.toml / Cargo.lock / migrations *.sql / *.wit). If
# any source file is newer than the image, the running container is stale.
printf '\nImage freshness (vs working tree)\n'
# Newest tracked build-input mtime, EXCLUDING the sibling binary's exclusive
# dir (a worker/ change doesn't rebuild the controller bin and vice-versa;
# shared talos-* crates still count for both). Python runs `git ls-files`
# itself — piping into `python3 - <<EOF` would collide with the heredoc.
newest_src_for() {  # $1 = dir prefix to exclude (e.g. "worker/")
  python3 - "$1" <<'PY' 2>/dev/null || printf '0\t'
import os, subprocess, sys
exclude = sys.argv[1] if len(sys.argv) > 1 else ""
out = subprocess.run(
    ["git", "ls-files", "--", "*.rs", "*.toml", "Cargo.lock", "migrations/*.sql", "*.wit"],
    capture_output=True, text=True,
).stdout
newest = 0.0
newest_path = ""
for p in out.splitlines():
    if exclude and p.startswith(exclude):
        continue
    try:
        m = os.path.getmtime(p)
    except OSError:
        continue
    if m > newest:
        newest, newest_path = m, p
print(f"{int(newest)}\t{newest_path}")
PY
}
for svc in controller worker; do
  cid=$(docker compose ps -q "$svc" 2>/dev/null)
  [ -z "$cid" ] && { warn "$svc: not running — can't check freshness"; continue; }
  # Exclude the OTHER bin's dir from this service's freshness inputs.
  sibling="worker/"; [ "$svc" = "worker" ] && sibling="controller/"
  src=$(newest_src_for "$sibling")
  newest_epoch=$(printf '%s' "$src" | cut -f1)
  newest_path=$(printf '%s' "$src" | cut -f2)
  img=$(docker inspect "$cid" --format '{{.Image}}' 2>/dev/null)
  created=$(docker image inspect "$img" --format '{{.Created}}' 2>/dev/null)
  img_epoch=$(python3 - "$created" <<'PY' 2>/dev/null || echo 0
import sys, datetime
s = (sys.argv[1] if len(sys.argv) > 1 else "").strip()
# RFC3339 with optional fractional seconds + Z; trim to seconds for fromisoformat.
s = s.replace("Z", "+00:00")
if "." in s:
    head, _, tail = s.partition(".")
    # keep tz suffix after the fractional part
    tz = ""
    for i, c in enumerate(tail):
        if c in "+-":
            tz = tail[i:]; break
    s = head + tz
try:
    print(int(datetime.datetime.fromisoformat(s).timestamp()))
except Exception:
    print(0)
PY
)
  if [ "${img_epoch:-0}" = "0" ] || [ "${newest_epoch:-0}" = "0" ]; then
    warn "$svc: could not determine freshness"
    continue
  fi
  if [ "$newest_epoch" -gt "$img_epoch" ]; then
    age_h=$(( (newest_epoch - img_epoch) / 3600 ))
    bad "$svc image is STALE — source is ${age_h}h newer than the built image"
    hint "newest source: ${newest_path:-?}"
    hint "rebuild with: make rebuild SERVICE=$svc"
  else
    pass "$svc image is fresh (newer than all tracked source)"
  fi
done

# ── 5. Dev prerequisites ────────────────────────────────────────────────
printf '\nPrerequisites\n'
if [ -f .env ]; then pass ".env present"; else warn ".env missing"; hint "make setup"; fi
if [ -d frontend/node_modules ]; then
  pass "frontend/node_modules present (make lint-frontend will run)"
else
  warn "frontend/node_modules absent — make lint-frontend skips the frontend gate"
  hint "cd frontend && npm ci"
fi

# ── Summary ─────────────────────────────────────────────────────────────
printf '\n'
if [ "$ISSUES" -eq 0 ]; then
  printf '%s✓ no issues — good to live-test.%s\n' "$GREEN" "$RST"
else
  printf '%s⚠ %d issue(s) above — see the ↳ fix hints.%s\n' "$YEL" "$ISSUES" "$RST"
fi
exit 0
