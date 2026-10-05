#!/usr/bin/env bash
# Tests for scripts/confirm-deploy.sh.
#
# The script answers "is origin/main what is running, and is it healthy?" with
# PASS / FAIL / UNKNOWN per check. Against a healthy stack only the PASS arms
# run, so every other arm is driven here: fake `git`, `docker` and `curl` on
# PATH and a copy of the script in a throwaway tree with its own migrations/.
# No daemon, controller or network is touched, so this runs anywhere (CI:
# quality.yml `audit` job).
#
# It also pins the script's one promise: across every scenario the fakes log
# each call, and the log may contain only the read-only calls listed at the
# bottom.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

fails=0
check() { # check <label> <expected> <actual>
    if [ "$2" = "$3" ]; then printf '  ok   %s\n' "$1"; else printf '  FAIL %s\n       expected: %s\n       actual:   %s\n' "$1" "$2" "$3"; fails=$((fails+1)); fi
}
has() { if printf '%s' "$1" | grep -qF -- "$2"; then echo yes; else echo no; fi; }
line_for() { printf '%s\n' "$1" | grep -F -- "$2" | head -1 || true; }

T="$(mktemp -d)"
# A run that stops early must FAIL: on macOS bash 3.2 an abort inside an `if`
# exits 0 and skips every later check (the launchd-path test's measured lesson).
completed=""
on_exit() {
    local st=$?
    rm -rf "$T"
    if [[ -z "$completed" ]]; then
        echo "✗ confirm-deploy test stopped before its last check (status $st)" >&2
        exit 1
    fi
    exit "$st"
}
trap on_exit EXIT

MAIN="aaaaaaa1111111111111111111111111111111aa"
OTHER="bbbbbbb2222222222222222222222222222222bb"

# ── The throwaway tree ──────────────────────────────────────────────────
mkdir -p "$T/repo/scripts" "$T/repo/migrations" "$T/bin"
cp "$REPO/scripts/confirm-deploy.sh" "$T/repo/scripts/confirm-deploy.sh"
SCRIPT="$T/repo/scripts/confirm-deploy.sh"
: > "$T/repo/migrations/001_first.sql"
: > "$T/repo/migrations/20260101000000_second.sql"
: > "$T/repo/migrations/20260102000000_third.sql"
: > "$T/repo/migrations/README.md"

# ── The fakes. Behaviour comes from the environment; every call is logged. ─
cat > "$T/bin/git" <<'SHIM'
#!/usr/bin/env bash
echo "git $*" >> "$SHIM_LOG"
case "$*" in
  "ls-remote origin refs/heads/main")
    [ -n "${SHIM_MAIN:-}" ] || exit 128
    printf '%s\trefs/heads/main\n' "$SHIM_MAIN" ;;
  "rev-parse HEAD")
    [ -n "${SHIM_HEAD:-}" ] || exit 128
    printf '%s\n' "$SHIM_HEAD" ;;
  "remote get-url origin")
    [ -n "${SHIM_ORIGIN:-}" ] || exit 2
    printf '%s\n' "$SHIM_ORIGIN" ;;
  *) exit 1 ;;
esac
SHIM

cat > "$T/bin/docker" <<'SHIM'
#!/usr/bin/env bash
echo "docker $*" >> "$SHIM_LOG"
case "$1" in
  info)
    [ "${SHIM_DOCKER_DOWN:-}" = 1 ] && exit 1
    exit 0 ;;
  inspect)
    for name in "$@"; do :; done
    case "$name" in
      talos-controller) state="${SHIM_CONTROLLER_STATE:-running}" ;;
      talos-worker-1)   state="${SHIM_WORKER_STATE:-running}" ;;
      *)                exit 1 ;;
    esac
    [ "$state" = absent ] && exit 1
    printf '%s|2026-01-02T03:04:05.000000001Z|0\n' "$state" ;;
  exec)
    [ -n "${SHIM_ROWS:-}" ] || exit 1
    cat "$SHIM_ROWS" ;;
  logs)
    [ -n "${SHIM_LOGFILE:-}" ] || exit 1
    cat "$SHIM_LOGFILE" ;;
  *) exit 1 ;;
esac
SHIM

cat > "$T/bin/curl" <<'SHIM'
#!/usr/bin/env bash
url=""; body=""; prev=""
for a in "$@"; do
  case "$prev" in -d) body="$a" ;; esac
  case "$a" in http://*|https://*) url="$a" ;; esac
  prev="$a"
done
method=GET
[ -n "$body" ] && method=POST
echo "curl $method $url $body" >> "$SHIM_LOG"
case "$url" in
  https://api.github.com/repos/*/actions/workflows/quality.yml/runs\?*)
    [ -n "${SHIM_RUNS:-}" ] || exit 7
    cat "$SHIM_RUNS" ;;
  https://api.github.com/repos/*/actions/runs/*/jobs\?*)
    [ -n "${SHIM_JOBS:-}" ] || exit 7
    cat "$SHIM_JOBS" ;;
  https://api.github.com/*)
    # The body the `application/vnd.github.sha` media type answers with: the
    # commit and nothing else. Anything else (a 404's JSON) is not a commit.
    [ -n "${SHIM_API:-}" ] || exit 7
    printf '%s' "$SHIM_API" ;;
  */health)
    if [ "${SHIM_HEALTH_CODE:-200}" = 000 ]; then printf '\n000'; exit 7; fi
    printf '%s\n%s' "${SHIM_HEALTH_BODY:-{\"status\":\"ok\"\}}" "${SHIM_HEALTH_CODE:-200}" ;;
  */mcp/local)
    case "$body" in
      *get_platform_info*) [ -n "${SHIM_INFO:-}" ] || exit 7; cat "$SHIM_INFO" ;;
      *tools/list*)        [ -n "${SHIM_TOOLS:-}" ] || exit 7; cat "$SHIM_TOOLS" ;;
      *) exit 7 ;;
    esac ;;
  *) exit 7 ;;
esac
SHIM
chmod +x "$T/bin/git" "$T/bin/docker" "$T/bin/curl"

# mk_info <file> <controller build_version> [worker build_version | none | withheld]
mk_info() {
    python3 - "$1" "$2" "${3:-}" <<'PY'
import json, sys
path, build, worker = sys.argv[1], sys.argv[2], sys.argv[3]
info = {"build_version": build, "uptime_seconds": 12}
if worker == "withheld":
    info["fleet"] = None
else:
    rows = [{"source": "static-env", "worker_id": "w-example", "build_version": None}]
    if worker and worker != "none":
        rows.insert(0, {"source": "registered", "worker_id": "w-example", "build_version": worker})
    info["fleet"] = {"workers": rows, "truncated": False}
reply = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": json.dumps(info)}]}}
open(path, "w").write(json.dumps(reply))
PY
}

mk_info "$T/info-good.json"     "0.1.0+aaaaaaa"       "0.1.0+aaaaaaa"
mk_info "$T/info-other.json"    "0.1.0+bbbbbbb"       "0.1.0+aaaaaaa"
mk_info "$T/info-dirty.json"    "0.1.0+aaaaaaa-dirty" "0.1.0+aaaaaaa"
mk_info "$T/info-unknown.json"  "0.1.0+unknown"       "0.1.0+aaaaaaa"
mk_info "$T/info-override.json" "9.9.9"               "0.1.0+aaaaaaa"
mk_info "$T/info-worker.json"   "0.1.0+aaaaaaa"       "0.1.0+bbbbbbb"
mk_info "$T/info-nowork.json"   "0.1.0+aaaaaaa"       "none"
mk_info "$T/info-withheld.json" "0.1.0+aaaaaaa"       "withheld"
printf '{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"refused"}}' > "$T/info-error.json"

printf '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"a"},{"name":"b"},{"name":"c"}]}}' > "$T/tools-3.json"
printf '{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}' > "$T/tools-0.json"
printf '<html>not found</html>' > "$T/tools-html.txt"

printf '1|t\n20260101000000|t\n20260102000000|t\n' > "$T/rows-all"
printf '1|t\n20260101000000|t\n' > "$T/rows-missing"
printf '1|t\n20260101000000|t\n20260102000000|f\n' > "$T/rows-failed"
printf '1|t\n20260101000000|t\n20260102000000|t\n20260103000000|t\n' > "$T/rows-ahead"

# mk_runs <file> <head sha> <status:conclusion:event:created> …  (newest need not be first)
mk_runs() {
    python3 - "$@" <<'PY'
import json, sys
path, sha, specs = sys.argv[1], sys.argv[2], sys.argv[3:]
runs = []
for i, spec in enumerate(specs):
    status, conclusion, event, created = spec.split(":")
    runs.append({"id": 9000 + i, "head_sha": sha, "status": status,
                 "conclusion": conclusion or None, "event": event,
                 "created_at": "2026-01-02T0%s:00:00Z" % created,
                 "updated_at": "2026-01-02T0%s:30:00Z" % created,
                 "html_url": "https://github.com/example-owner/example-repo/actions/runs/%d" % (9000 + i)})
open(path, "w").write(json.dumps({"total_count": len(runs), "workflow_runs": runs}))
PY
}
mk_runs "$T/runs-pass.json"     "$MAIN"  "completed:success:push:1"
mk_runs "$T/runs-fail.json"     "$MAIN"  "completed:failure:push:1"
mk_runs "$T/runs-running.json"  "$MAIN"  "in_progress::push:1"
mk_runs "$T/runs-none.json"     "$MAIN"
mk_runs "$T/runs-other.json"    "$OTHER" "completed:success:push:1"
# A later scheduled run of the same commit failed after its push run passed,
# listed oldest-last to prove the newest decides, not the first row.
mk_runs "$T/runs-later-fail.json" "$MAIN" "completed:failure:schedule:5" "completed:success:push:1"
mk_runs "$T/runs-rerun.json"      "$MAIN" "in_progress::push:5" "completed:failure:push:1"
printf '{"message":"API rate limit exceeded for 192.0.2.1.","documentation_url":"https://example.test"}' > "$T/runs-limited.json"
printf '<html>bad gateway</html>' > "$T/runs-html.txt"
python3 - "$T/runs-hostile.json" "$MAIN" <<'PY'
import json, sys
path, sha = sys.argv[1], sys.argv[2]
run = {"id": "9000; rm -rf /", "head_sha": sha, "status": "completed", "conclusion": "failure\x1b[31m",
       "event": "push", "created_at": "2026-01-02T01:00:00Z", "updated_at": "2026-01-02T01:30:00Z",
       "html_url": "https://evil.example.test/x"}
open(path, "w").write(json.dumps({"workflow_runs": [run]}))
PY
python3 - "$T/jobs-two.json" <<'PY'
import json, sys
jobs = [{"name": "Lint (rustfmt + structural checks)", "conclusion": "success"},
        {"name": "Frontend (lint + test)", "conclusion": "failure"},
        {"name": "Clippy (-D warnings)", "conclusion": "skipped"},
        {"name": "Quality gate", "conclusion": "failure"}]
open(sys.argv[1], "w").write(json.dumps({"total_count": len(jobs), "jobs": jobs}))
PY

E=$'\033'
{
    printf '%s[2m2026-01-02T03:04:06.000001Z%s[0m %s[32m INFO%s[0m %s[2mtalos_example%s[0m: started\n' "$E" "$E" "$E" "$E" "$E" "$E"
    printf '%s[2m2026-01-02T03:04:07.000001Z%s[0m %s[33m WARN%s[0m talos_example: slow\n' "$E" "$E" "$E" "$E"
    printf '%s[2m2026-01-02T03:04:08.000001Z%s[0m %s[32m INFO%s[0m talos_example: upstream said ERROR again\n' "$E" "$E" "$E" "$E"
} > "$T/log-clean"
{
    cat "$T/log-clean"
    printf '%s[2m2026-01-02T03:04:09.000001Z%s[0m %s[31mERROR%s[0m talos_example: first failure\n' "$E" "$E" "$E" "$E"
    printf '%s[2m2026-01-02T03:04:10.000001Z%s[0m %s[31mERROR%s[0m talos_example: call refused authorization=Bearer abcdefghijklmnop0123 token=zzzzzzzzzzzz\n' "$E" "$E" "$E" "$E"
    printf '%s[2m2026-01-02T03:04:11.000001Z%s[0m %s[31mERROR%s[0m talos_example: long %s\n' "$E" "$E" "$E" "$E" \
        "$(python3 -c 'print("x" * 400)')"
    printf '%s[2m2026-01-02T03:04:12.000001Z%s[0m %s[31mERROR%s[0m talos_example: fourth failure\n' "$E" "$E" "$E" "$E"
    printf "thread 'tokio-runtime-worker' panicked at src/example.rs:1:1:\n"
} > "$T/log-errors"

: > "$T/shim.log"

# run <label> [VAR=value …] — runs the script with the healthy defaults,
# overridden by the given assignments. Sets OUT and RC.
run() {
    shift
    set +e
    OUT="$(env PATH="$T/bin:$PATH" SHIM_LOG="$T/shim.log" NO_COLOR=1 \
        SHIM_MAIN="$MAIN" SHIM_HEAD="$MAIN" \
        SHIM_ORIGIN="git@github.com:example-owner/example-repo.git" SHIM_RUNS="$T/runs-pass.json" \
        SHIM_INFO="$T/info-good.json" SHIM_TOOLS="$T/tools-3.json" \
        SHIM_ROWS="$T/rows-all" SHIM_LOGFILE="$T/log-clean" \
        "$@" "${BASH_BIN:-bash}" ${BASH_FLAGS:-} "$SCRIPT" 2>&1)"
    RC=$?
    set -e
}
count() { printf '%s\n' "$OUT" | grep -c "^$1 " || true; }

echo "healthy stack"
run healthy
check "exit 0"                          0   "$RC"
check "9 PASS lines"                    9   "$(count PASS)"
check "no FAIL line"                    0   "$(count FAIL)"
check "no UNKNOWN line"                 0   "$(count UNKNOWN)"
check "7-char build equals 40-char main" yes "$(has "$OUT" "controller commit     running aaaaaaa = origin/main aaaaaaa11111, built from a clean tree")"
check "migration count and newest"      yes "$(has "$OUT" "3 of 3 local files applied, newest 20260102000000")"
check "says what it compared against"   yes "$(has "$OUT" "compared against the local checkout, aaaaaaa = origin/main")"
check "tool count reported"             yes "$(has "$OUT" "3 tools listed")"
check "an INFO line quoting ERROR is not counted" yes "$(has "$OUT" "0 ERROR lines in 3 log line(s)")"
check "summary"                         yes "$(has "$OUT" "9 checks — 9 PASS, 0 FAIL, 0 UNKNOWN. Exit 0.")"

echo "the same run under bash -e, and under -u -o pipefail"
BASH_FLAGS="-e" run healthy-e
check "bash -e: exit 0"                 0   "$RC"
check "bash -e: 9 PASS"                 9   "$(count PASS)"
BASH_FLAGS="-u -o pipefail" run healthy-u
check "bash -u -o pipefail: exit 0"     0   "$RC"
check "bash -u -o pipefail: 9 PASS"     9   "$(count PASS)"
BASH_FLAGS="-e" run failing-e SHIM_INFO="$T/info-other.json" SHIM_DOCKER_DOWN=1 SHIM_TOOLS=""
check "bash -e, failing stack: still reaches the summary" yes "$(has "$OUT" "confirm-deploy: 9 checks")"
check "bash -e, failing stack: exit 1"  1   "$RC"

echo "the commit"
run other SHIM_INFO="$T/info-other.json"
check "another commit: exit 1"          1   "$RC"
check "another commit: FAIL names both" yes "$(has "$OUT" "FAIL     controller commit     running bbbbbbb, but origin/main aaaaaaa11111")"
run dirty SHIM_INFO="$T/info-dirty.json"
check "dirty build: exit 0"             0   "$RC"
check "dirty build: UNKNOWN, not PASS"  yes "$(has "$(line_for "$OUT" "controller commit")" "UNKNOWN")"
check "dirty build: says dirty"         yes "$(has "$OUT" "running aaaaaaa-dirty")"
check "UNKNOWN alone: summary says so"  yes "$(has "$OUT" "8 PASS, 0 FAIL, 1 UNKNOWN. Exit 0: UNKNOWN alone does not fail")"
run unknown SHIM_INFO="$T/info-unknown.json"
check "sha 'unknown': UNKNOWN"          yes "$(has "$(line_for "$OUT" "controller commit")" "UNKNOWN")"
run override SHIM_INFO="$T/info-override.json"
check "no +sha at all: UNKNOWN"         yes "$(has "$(line_for "$OUT" "controller commit")" "UNKNOWN")"
run rpc-error SHIM_INFO="$T/info-error.json"
check "JSON-RPC error: UNKNOWN"         yes "$(has "$(line_for "$OUT" "controller commit")" "UNKNOWN")"
check "JSON-RPC error: exit 0"          0   "$RC"
run no-info SHIM_INFO=""
check "no answer: UNKNOWN"              yes "$(has "$(line_for "$OUT" "controller commit")" "UNKNOWN")"
run no-main SHIM_MAIN=""
check "origin/main unreadable: UNKNOWN" yes "$(has "$(line_for "$OUT" "controller commit")" "UNKNOWN")"
check "origin/main unreadable: exit 0"  0   "$RC"
check "origin/main unreadable: said"    yes "$(has "$OUT" "origin/main     unreadable")"

echo "git cannot ask (a locked SSH agent): the GitHub API is asked instead"
GH='git@github.com:example-owner/example-repo.git'
run api-ssh SHIM_MAIN="" SHIM_ORIGIN="$GH" SHIM_API="$MAIN"
check "api answers: commit check PASSES" yes "$(has "$(line_for "$OUT" "controller commit")" "PASS")"
check "api answers: 9 PASS, exit 0"     "9 0" "$(count PASS) $RC"
check "api answers: says where it read it" yes "$(has "$OUT" "(from the GitHub API; git ls-remote origin failed)")"
run api-https SHIM_MAIN="" SHIM_ORIGIN="https://github.com/example-owner/example-repo" SHIM_API="$MAIN"
check "https origin: commit check PASSES" yes "$(has "$(line_for "$OUT" "controller commit")" "PASS")"
run api-other SHIM_MAIN="" SHIM_ORIGIN="$GH" SHIM_API="$OTHER" SHIM_INFO="$T/info-good.json"
check "api names another commit: FAIL"  "yes 1" "$(has "$(line_for "$OUT" "controller commit")" "FAIL") $RC"
run api-404 SHIM_MAIN="" SHIM_ORIGIN="$GH" SHIM_API='{"message":"Not Found","status":"404"}'
check "api answers without a commit: UNKNOWN" yes "$(has "$(line_for "$OUT" "controller commit")" "UNKNOWN")"
check "api answers without a commit: said" yes "$(has "$OUT" "the GitHub API gave no commit")"
run api-short SHIM_MAIN="" SHIM_ORIGIN="$GH" SHIM_API="aaaaaaa"
check "a short hash is not a commit: UNKNOWN" yes "$(has "$(line_for "$OUT" "controller commit")" "UNKNOWN")"
run api-down SHIM_MAIN="" SHIM_ORIGIN="$GH" SHIM_API=""
check "api unreachable: UNKNOWN, exit 0" "yes 0" "$(has "$(line_for "$OUT" "controller commit")" "UNKNOWN") $RC"
: > "$T/before-elsewhere.log"; cp "$T/shim.log" "$T/before-elsewhere.log"
run api-elsewhere SHIM_MAIN="" SHIM_ORIGIN="git@git.example.test:example-owner/example-repo.git" SHIM_API="$MAIN"
check "origin not on github.com: UNKNOWN" yes "$(has "$(line_for "$OUT" "controller commit")" "UNKNOWN")"
asked_api="$(tail -n +"$(( $(grep -c . "$T/before-elsewhere.log") + 1 ))" "$T/shim.log" | grep -c 'api.github.com' || true)"
check "origin not on github.com: the API is never asked" 0 "$asked_api"
run api-injected SHIM_MAIN="" SHIM_ORIGIN='https://github.com/example-owner/example-repo/../../other?x=1' SHIM_API="$MAIN"
check "an origin that is not owner/repo is not sent anywhere" yes "$(has "$(line_for "$OUT" "controller commit")" "UNKNOWN")"
run git-works SHIM_ORIGIN="$GH" SHIM_API="$OTHER"
check "git answers: the API is not consulted" yes "$(has "$(line_for "$OUT" "controller commit")" "PASS")"
run moved SHIM_MAIN="$OTHER"
check "main moved on: FAIL"             yes "$(has "$OUT" "running aaaaaaa, but origin/main bbbbbbb22222")"
check "main moved on: migrations line says the checkout is not main" yes "$(has "$OUT" "local checkout aaaaaaa, which is NOT origin/main bbbbbbb")"

echo "the worker's commit"
run worker SHIM_INFO="$T/info-worker.json"
check "worker on another commit: exit 1" 1  "$RC"
check "worker on another commit: FAIL"  yes "$(has "$(line_for "$OUT" "worker commit")" "FAIL")"
check "worker on another commit: named" yes "$(has "$OUT" "w-example=0.1.0+bbbbbbb")"
run nowork SHIM_INFO="$T/info-nowork.json"
check "no registered worker: UNKNOWN"   yes "$(has "$(line_for "$OUT" "worker commit")" "UNKNOWN")"
run withheld SHIM_INFO="$T/info-withheld.json"
check "fleet withheld: UNKNOWN"         yes "$(has "$(line_for "$OUT" "worker commit")" "UNKNOWN")"

echo "containers and health"
run exited SHIM_WORKER_STATE=exited
check "exited worker: FAIL"             yes "$(has "$OUT" "FAIL     worker container      talos-worker-1 is exited, not running")"
run absent SHIM_CONTROLLER_STATE=absent
check "no controller container: FAIL"   yes "$(has "$OUT" "FAIL     controller container  no container named talos-controller")"
check "…and its log is UNKNOWN"         yes "$(has "$(line_for "$OUT" "controller log")" "UNKNOWN")"
run docker-down SHIM_DOCKER_DOWN=1
check "docker down: exit 0"             0   "$RC"
check "docker down: 4 UNKNOWN"          4   "$(count UNKNOWN)"
check "docker down: no FAIL"            0   "$(count FAIL)"
run h503 SHIM_HEALTH_CODE=503
check "/health 503: FAIL"               yes "$(has "$OUT" "FAIL     controller health     GET /health answered 503")"
run degraded SHIM_HEALTH_BODY='{"status":"degraded"}'
check "/health 200 degraded: FAIL"      yes "$(has "$OUT" "answered 200 but status is 'degraded', not ok")"
run h000 SHIM_HEALTH_CODE=000
check "/health no answer: FAIL"         yes "$(has "$(line_for "$OUT" "controller health")" "got no answer")"

echo "migrations"
run missing SHIM_ROWS="$T/rows-missing"
check "missing migration: exit 1"       1   "$RC"
check "missing migration: named"        yes "$(has "$OUT" "1 of 3 local file(s) have no successful row (first: 20260102000000)")"
run failed SHIM_ROWS="$T/rows-failed"
check "success = false: FAIL"           yes "$(has "$OUT" "1 row(s) recorded success = false (first: 20260102000000)")"
run ahead SHIM_ROWS="$T/rows-ahead"
check "database ahead: still PASS"      yes "$(has "$(line_for "$OUT" "migrations")" "PASS")"
check "database ahead: said"            yes "$(has "$OUT" "1 applied version(s) are not in this checkout")"
run no-rows SHIM_ROWS=""
check "table unreadable: UNKNOWN"       yes "$(has "$(line_for "$OUT" "migrations")" "UNKNOWN")"

echo "the controller log"
run errors SHIM_LOGFILE="$T/log-errors"
check "ERROR lines: exit 1"             1   "$RC"
check "ERROR lines: count includes the panic" yes "$(has "$OUT" "5 ERROR line(s) in 8 log line(s)")"
check "first three shown, not the fourth" "yes no" "$(has "$OUT" "first failure") $(has "$OUT" "fourth failure")"
check "ANSI stripped"                   no  "$(has "$OUT" "$E")"
check "bearer value masked"             no  "$(has "$OUT" "abcdefghijklmnop0123")"
check "token value masked"              no  "$(has "$OUT" "zzzzzzzzzzzz")"
longest="$(printf '%s\n' "$OUT" | awk '/^         / { sub(/^         /, ""); if (length($0) > m) m = length($0) } END { print m + 0 }')"
check "samples cut at 160 characters"   160 "$longest"

echo "MCP tools/list"
run tools0 SHIM_TOOLS="$T/tools-0.json"
check "0 tools: FAIL"                   yes "$(has "$OUT" "listed 0 tools")"
run tools-html SHIM_TOOLS="$T/tools-html.txt"
check "not a tool list: FAIL"           yes "$(has "$OUT" "answered, but not with a tool list")"
run tools-none SHIM_TOOLS=""
check "no answer: FAIL, exit 1"         "yes 1" "$(has "$OUT" "FAIL     MCP tools/list        no answer") $RC"

echo "did the commit on main pass its checks"
run checks-pass
check "passing run: PASS, names the commit and the event" yes "$(has "$OUT" "PASS     checks on main        quality.yml passed for aaaaaaa (push run, finished 2026-01-02T01:30:00Z)")"
run checks-fail SHIM_RUNS="$T/runs-fail.json" SHIM_JOBS="$T/jobs-two.json"
check "failed run: FAIL, exit 1"         "yes 1" "$(has "$(line_for "$OUT" "checks on main")" "FAIL") $RC"
check "failed run: says what it concluded" yes "$(has "$OUT" "quality.yml concluded failure for aaaaaaa (push run")"
check "failed run: links the run"        yes "$(has "$OUT" "https://github.com/example-owner/example-repo/actions/runs/9000")"
check "failed run: names the jobs that did not pass, and only those" yes "$(has "$OUT" "did not pass: Frontend (lint + test); Quality gate")"
check "failed run: a skipped job is not named" no "$(has "$OUT" "Clippy")"
run checks-fail-nojobs SHIM_RUNS="$T/runs-fail.json" SHIM_JOBS=""
check "failed run, jobs unreadable: still FAIL" "yes 1" "$(has "$(line_for "$OUT" "checks on main")" "FAIL") $RC"
check "failed run, jobs unreadable: no job line invented" no "$(has "$OUT" "did not pass:")"
run checks-running SHIM_RUNS="$T/runs-running.json"
check "run in progress: UNKNOWN, exit 0" "yes 0" "$(has "$(line_for "$OUT" "checks on main")" "UNKNOWN") $RC"
check "run in progress: said"            yes "$(has "$OUT" "quality.yml is in_progress for aaaaaaa")"
run checks-none SHIM_RUNS="$T/runs-none.json"
check "no run for the commit: UNKNOWN, not PASS" yes "$(has "$(line_for "$OUT" "checks on main")" "UNKNOWN")"
check "no run for the commit: said"      yes "$(has "$OUT" "no quality.yml run exists for aaaaaaa")"
run checks-other SHIM_RUNS="$T/runs-other.json"
check "a passing run of ANOTHER commit is not this commit's pass" yes "$(has "$OUT" "UNKNOWN  checks on main        no quality.yml run exists for aaaaaaa")"
run checks-later-fail SHIM_RUNS="$T/runs-later-fail.json" SHIM_JOBS="$T/jobs-two.json"
check "the newest run decides: later failure after an earlier pass is FAIL" yes "$(has "$OUT" "FAIL     checks on main        quality.yml concluded failure for aaaaaaa (schedule run")"
check "…and the earlier result is stated" yes "$(has "$OUT" "an earlier run of this commit concluded success")"
run checks-rerun SHIM_RUNS="$T/runs-rerun.json"
check "a newer run in progress over an old failure: UNKNOWN" yes "$(has "$(line_for "$OUT" "checks on main")" "UNKNOWN")"
check "…and the old failure is stated"   yes "$(has "$OUT" "an earlier run of this commit concluded failure")"
run checks-limited SHIM_RUNS="$T/runs-limited.json"
check "rate limited: UNKNOWN, exit 0"    "yes 0" "$(has "$(line_for "$OUT" "checks on main")" "UNKNOWN") $RC"
check "rate limited: GitHub's reason shown" yes "$(has "$OUT" "API rate limit exceeded")"
run checks-html SHIM_RUNS="$T/runs-html.txt"
check "not JSON: UNKNOWN"                yes "$(has "$(line_for "$OUT" "checks on main")" "UNKNOWN")"
run checks-down SHIM_RUNS=""
check "API unreachable: UNKNOWN, exit 0" "yes 0" "$(has "$(line_for "$OUT" "checks on main")" "UNKNOWN") $RC"
run checks-no-origin SHIM_ORIGIN=""
check "origin unreadable: UNKNOWN"       yes "$(has "$OUT" "UNKNOWN  checks on main        origin is not a github.com repository")"
run checks-no-main SHIM_MAIN="" SHIM_API=""
check "origin/main unreadable: UNKNOWN"  yes "$(has "$OUT" "UNKNOWN  checks on main        origin/main could not be read")"
: > "$T/before-hostile.log"; cp "$T/shim.log" "$T/before-hostile.log"
run checks-hostile SHIM_RUNS="$T/runs-hostile.json" SHIM_JOBS="$T/jobs-two.json"
check "hostile reply: still a FAIL line" yes "$(has "$(line_for "$OUT" "checks on main")" "FAIL")"
check "hostile reply: escape bytes do not reach the terminal" no "$(has "$OUT" "$E")"
check "hostile reply: a link off github.com is not printed" no "$(has "$OUT" "evil.example.test")"
asked_jobs="$(tail -n +"$(( $(grep -c . "$T/before-hostile.log") + 1 ))" "$T/shim.log" | grep -c '/jobs' || true)"
check "hostile reply: a run id that is not a number is put in no URL" 0 "$asked_jobs"

echo "read-only: every call any scenario made"
unexpected="$(grep -v \
    -e '^git ls-remote origin refs/heads/main$' \
    -e '^git rev-parse HEAD$' \
    -e '^git remote get-url origin$' \
    -e '^curl GET https://api.github.com/repos/example-owner/example-repo/commits/main $' \
    -e '^curl GET https://api.github.com/repos/example-owner/example-repo/actions/workflows/quality.yml/runs?head_sha=[0-9a-f]\{40\}&per_page=20 $' \
    -e '^curl GET https://api.github.com/repos/example-owner/example-repo/actions/runs/[0-9]*/jobs?per_page=100 $' \
    -e '^docker info$' \
    -e '^docker inspect -f [^ ]* talos-[a-z0-9-]*$' \
    -e '^docker logs --since [^ ]* talos-controller$' \
    -e '^docker exec -e PGOPTIONS=-c default_transaction_read_only=on talos-postgres psql -U talos -d talos -At -v ON_ERROR_STOP=1 -c SELECT version, success FROM _sqlx_migrations ORDER BY version$' \
    -e '^curl GET http://localhost:8000/health $' \
    -e '^curl POST http://localhost:8000/mcp/local {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_platform_info","arguments":{}}}$' \
    -e '^curl POST http://localhost:8000/mcp/local {"jsonrpc":"2.0","id":2,"method":"tools/list"}$' \
    "$T/shim.log" || true)"
check "no call outside the read-only list" "" "$unexpected"
check "the fakes were called"           yes "$([ "$(grep -c . "$T/shim.log")" -gt 100 ] && echo yes || echo no)"

completed=1
if [ "$fails" -gt 0 ]; then
    echo "✗ $fails check(s) failed"
    exit 1
fi
echo "✓ confirm-deploy: all checks passed"
