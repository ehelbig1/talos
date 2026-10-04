#!/usr/bin/env bash
# `make confirm-deploy` — after `git pull && make up`: is the commit on
# origin/main the commit that is running, and is the stack healthy?
#
# Until this script that was answered by hand and by INFERENCE ("the
# controller container started after the merge"). A start time says when a
# container started, not what it was built from. The controller already
# reports the commit it was built from — `get_platform_info.build_version`,
# `<package version>+<7-char sha>[-dirty]`, stamped at compile time by
# `talos-mcp-handlers/build.rs` — so the comparison can be exact.
#
# READ-ONLY. Everything this script sends:
#   git ls-remote origin refs/heads/main   (no fetch, checkout untouched)
#   git rev-parse HEAD
#   docker info / docker inspect / docker logs
#   docker exec <postgres> psql … one SELECT, in a read-only session
#   GET  <controller>/health
#   POST <controller>/mcp/local   tools/call get_platform_info, and tools/list
# It restarts nothing, writes nothing, migrates nothing, triggers nothing.
# (The controller logs one INFO line per MCP call it serves, as it does for
# any caller.)
#
# One line per check: PASS / FAIL / UNKNOWN.
#   FAIL     the check was made and the answer is wrong
#   UNKNOWN  the check could not be made (something was unreadable); this is
#            NOT a pass, and it is not counted as a failure either
# Exit status: 1 if any check FAILED, else 0 — UNKNOWN alone exits 0, and the
# summary line says so. 2 = the script itself could not run (a tool missing).
#
# Env vars (all optional):
#   CONTROLLER_URL              default http://localhost:8000
#   CONFIRM_DEPLOY_CONTROLLER   controller container, default talos-controller
#   CONFIRM_DEPLOY_WORKER       worker container,     default talos-worker-1
#   CONFIRM_DEPLOY_POSTGRES     postgres container,   default talos-postgres
#   CONFIRM_DEPLOY_PG_USER      default talos
#   CONFIRM_DEPLOY_PG_DB        default talos
#   CONFIRM_DEPLOY_TIMEOUT      per-request timeout, seconds, default 15
#   NO_COLOR                    set to anything to print without colour
#
# Written for `bash -e`, `set -u`, `set -o pipefail` and macOS bash 3.2: no
# associative arrays, no mapfile, and every command that may fail is tested
# by an `if`. Uses git, docker, curl, python3, sed and awk only.

set -euo pipefail

case "$0" in
    */*) cd "${0%/*}/.." ;;
    *)   cd .. ;;
esac

CONTROLLER_URL="${CONTROLLER_URL:-http://localhost:8000}"
CONTROLLER_URL="${CONTROLLER_URL%/}"
MCP_URL="$CONTROLLER_URL/mcp/local"
CONTROLLER="${CONFIRM_DEPLOY_CONTROLLER:-talos-controller}"
WORKER="${CONFIRM_DEPLOY_WORKER:-talos-worker-1}"
POSTGRES="${CONFIRM_DEPLOY_POSTGRES:-talos-postgres}"
PG_USER="${CONFIRM_DEPLOY_PG_USER:-talos}"
PG_DB="${CONFIRM_DEPLOY_PG_DB:-talos}"
TIMEOUT="${CONFIRM_DEPLOY_TIMEOUT:-15}"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    GREEN=$'\033[1;32m'; RED=$'\033[1;31m'; YEL=$'\033[1;33m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
    GREEN=""; RED=""; YEL=""; DIM=""; RST=""
fi

for tool in git docker curl python3 sed awk; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'confirm-deploy: %s is required and was not found\n' "$tool" >&2
        exit 2
    fi
done

PASS_N=0
FAIL_N=0
UNKNOWN_N=0

# report <PASS|FAIL|UNKNOWN> <check> <detail>
report() {
    local colour
    case "$1" in
        PASS)    PASS_N=$((PASS_N + 1));       colour="$GREEN" ;;
        FAIL)    FAIL_N=$((FAIL_N + 1));       colour="$RED" ;;
        *)       UNKNOWN_N=$((UNKNOWN_N + 1)); colour="$YEL" ;;
    esac
    printf '%s%-7s%s  %-20s  %s\n' "$colour" "$1" "$RST" "$2" "$3"
}

note() {
    printf '         %s%s%s\n' "$DIM" "$1" "$RST"
}

# The python helpers print "STATUS<TAB>check<TAB>detail" for a verdict and
# "><TAB>text" for an indented line under it. Fed by a here-document, never a
# pipe: a pipe would run this in a subshell and lose the counters.
emit() {
    local st name text
    while IFS=$'\t' read -r st name text || [ -n "$st" ]; do
        case "$st" in
            PASS|FAIL|UNKNOWN) report "$st" "$name" "$text" ;;
            '>')               note "$name" ;;
            '')                ;;
            *)                 report UNKNOWN "helper output" "a helper printed a line this script does not understand" ;;
        esac
    done
}

# `read -d ''` returns non-zero at end of input by design, hence `|| true`.

# stdin: the get_platform_info reply. argv: <origin/main sha or ''> <mcp url>
read -r -d '' PY_BUILD <<'PY' || true
import json, re, sys

expected, url = sys.argv[1], sys.argv[2]


def clean(s, limit=120):
    s = "".join(ch if ch.isprintable() else " " for ch in str(s))
    return s[:limit]


def out(status, check, detail):
    print("%s\t%s\t%s" % (status, check, clean(detail, 400)))


def split_build(build):
    """'0.1.0+326ae6f-dirty' -> ('326ae6f', True); no usable commit -> (None, dirty)."""
    if not isinstance(build, str) or "+" not in build:
        return None, False
    suffix = build.rsplit("+", 1)[1]
    dirty = suffix.endswith("-dirty")
    if dirty:
        suffix = suffix[: -len("-dirty")]
    if not re.fullmatch(r"[0-9a-f]{7,64}", suffix):
        return None, dirty
    return suffix, dirty


def same_commit(a, b):
    # The build carries 7 characters and git ls-remote prints 40: equal means
    # the shorter is a prefix of the longer.
    return a.startswith(b) or b.startswith(a)


raw = sys.stdin.read()
info = None
why = "no answer"
if raw.strip():
    try:
        reply = json.loads(raw)
        if isinstance(reply, dict) and reply.get("error"):
            why = "JSON-RPC error: %s" % clean(reply["error"].get("message", ""))
        else:
            info = json.loads(reply["result"]["content"][0]["text"])
            if not isinstance(info, dict):
                info, why = None, "the reply was not an object"
    except Exception:
        why = "the reply was not the expected JSON"

if info is None:
    out("UNKNOWN", "controller commit", "could not read get_platform_info at %s (%s)" % (url, why))
    out("UNKNOWN", "worker commit", "could not read get_platform_info at %s (%s)" % (url, why))
    sys.exit(0)

main = "origin/main %s" % expected[:12] if expected else "origin/main (unreadable)"

build = info.get("build_version")
sha, dirty = split_build(build)
if sha is None:
    out("UNKNOWN", "controller commit",
        "the controller reports build_version '%s', which names no commit "
        "(a TALOS_VERSION override, or an image built without GIT_SHA_OVERRIDE)" % clean(build))
elif not expected:
    out("UNKNOWN", "controller commit",
        "running %s%s; origin/main could not be read (git ls-remote failed)"
        % (sha, "-dirty" if dirty else ""))
elif not same_commit(sha, expected):
    out("FAIL", "controller commit",
        "running %s%s, but %s" % (sha, "-dirty" if dirty else "", main))
elif dirty:
    out("UNKNOWN", "controller commit",
        "running %s-dirty: the commit is %s, but the image was built from a tree "
        "with uncommitted changes, so it is not provably that commit" % (sha, main))
else:
    out("PASS", "controller commit", "running %s = %s, built from a clean tree" % (sha, main))

# The worker's build is what each REGISTERED worker row reported when it
# registered. A worker known only by a pinned key reports nothing.
fleet = info.get("fleet")
if not isinstance(fleet, dict):
    out("UNKNOWN", "worker commit", "the controller withheld the fleet report from this caller")
    sys.exit(0)
rows = [w for w in fleet.get("workers") or [] if isinstance(w, dict) and w.get("source") == "registered"]
if not rows:
    out("UNKNOWN", "worker commit", "no registered worker has reported a build")
    sys.exit(0)

wrong, unreadable, dirty_rows, good = [], [], [], []
for w in rows:
    wsha, wdirty = split_build(w.get("build_version"))
    label = "%s=%s" % (clean(w.get("worker_id"), 40), clean(w.get("build_version"), 40))
    if wsha is None:
        unreadable.append(label)
    elif expected and not same_commit(wsha, expected):
        wrong.append(label)
    elif wdirty:
        dirty_rows.append(label)
    else:
        good.append(label)

basis = "self-reported at registration"
if wrong:
    out("FAIL", "worker commit", "%d of %d registered worker row(s) report another commit than %s: %s (%s)"
        % (len(wrong), len(rows), main, ", ".join(wrong[:3]), basis))
elif not expected:
    out("UNKNOWN", "worker commit", "%d registered worker row(s) report %s; origin/main could not be read"
        % (len(rows), ", ".join((good + dirty_rows + unreadable)[:3])))
elif unreadable or dirty_rows:
    out("UNKNOWN", "worker commit", "%d of %d registered worker row(s) name no clean commit: %s (%s)"
        % (len(unreadable) + len(dirty_rows), len(rows), ", ".join((unreadable + dirty_rows)[:3]), basis))
else:
    out("PASS", "worker commit", "%d registered worker row(s) report %s (%s)%s"
        % (len(good), main, basis, "; the report was truncated" if fleet.get("truncated") else ""))
PY

# stdin: `version|t` rows from _sqlx_migrations.
# argv: <migrations dir> <local HEAD sha or ''> <origin/main sha or ''>
read -r -d '' PY_MIGRATIONS <<'PY' || true
import os, re, sys

mig_dir, head, expected = sys.argv[1], sys.argv[2], sys.argv[3]

local, unparsed = set(), 0
for name in os.listdir(mig_dir):
    if not name.endswith(".sql") or name.endswith(".down.sql"):
        continue
    m = re.match(r"(\d+)_", name)
    if m:
        local.add(int(m.group(1)))
    else:
        unparsed += 1

ok, failed = set(), set()
for line in sys.stdin:
    parts = line.strip().split("|")
    if len(parts) != 2 or not parts[0].isdigit():
        continue
    (ok if parts[1] == "t" else failed).add(int(parts[0]))

if not head:
    basis = "compared against the local checkout (commit unreadable)"
elif expected and (expected.startswith(head) or head.startswith(expected)):
    basis = "compared against the local checkout, %s = origin/main" % head[:7]
elif expected:
    basis = ("compared against the local checkout %s, which is NOT origin/main %s"
             % (head[:7], expected[:7]))
else:
    basis = "compared against the local checkout %s (origin/main unreadable)" % head[:7]

if not local:
    print("UNKNOWN\tmigrations\tno migration files found in %s/" % mig_dir)
    sys.exit(0)

missing = sorted(local - ok)
failed_rows = sorted(failed)
extra = len(ok - local)
tail = ""
if extra:
    tail += "; %d applied version(s) are not in this checkout" % extra
if unparsed:
    tail += "; %d .sql file(s) with no version prefix were skipped" % unparsed

if missing or failed_rows:
    bits = []
    if missing:
        bits.append("%d of %d local file(s) have no successful row (first: %s)"
                    % (len(missing), len(local), ", ".join(str(v) for v in missing[:3])))
    if failed_rows:
        bits.append("%d row(s) recorded success = false (first: %s)"
                    % (len(failed_rows), ", ".join(str(v) for v in failed_rows[:3])))
    print("FAIL\tmigrations\t%s; %s%s" % ("; ".join(bits), basis, tail))
else:
    print("PASS\tmigrations\t%d of %d local files applied, newest %d; %s%s"
          % (len(local), len(local), max(local), basis, tail))
PY

# stdin: the controller log since it started. Prints the verdict and up to
# three sample lines: ANSI stripped, credential-shaped text masked, 160 chars.
read -r -d '' PY_LOG <<'PY' || true
import re, sys

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# tracing's fmt layer prints `<timestamp> <LEVEL> <target>: …`; a line counts
# when its LEVEL is ERROR, not when the word appears inside a message.
LEVEL = re.compile(r"^\S+\s+ERROR\s")
PANIC = re.compile(r"^thread '.*' panicked at")
MASKS = [
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"), r"\1[masked]"),
    (re.compile(r"\b(sk-|ghp_|gho_|ghs_|ghu_|github_pat_|xox[abprs]-)[A-Za-z0-9_-]{8,}"), r"\1[masked]"),
    (re.compile(r"(?i)((?:password|passwd|secret|token|api[_-]?key|authorization)\"?\s*[=:]\s*\"?)[^\s\",]{4,}"),
     r"\1[masked]"),
]

since = sys.argv[1]
total = errors = 0
samples = []
for raw in sys.stdin.buffer:
    total += 1
    line = ANSI.sub("", raw.decode("utf-8", "replace")).rstrip("\r\n")
    if not (LEVEL.match(line) or PANIC.match(line)):
        continue
    errors += 1
    if len(samples) < 3:
        for pattern, repl in MASKS:
            line = pattern.sub(repl, line)
        line = "".join(ch if ch.isprintable() else " " for ch in line)
        samples.append(line[:160])

if errors:
    print("FAIL\tcontroller log\t%d ERROR line(s) in %d log line(s) since the controller started at %s"
          % (errors, total, since))
    for s in samples:
        print(">\t%s" % s)
else:
    print("PASS\tcontroller log\t0 ERROR lines in %d log line(s) since the controller started at %s"
          % (total, since))
PY

# stdin: the tools/list reply. argv: <mcp url>
read -r -d '' PY_TOOLS <<'PY' || true
import json, sys

url = sys.argv[1]
raw = sys.stdin.read()
if not raw.strip():
    print("FAIL\tMCP tools/list\tno answer from %s" % url)
    sys.exit(0)
try:
    reply = json.loads(raw)
    tools = reply["result"]["tools"]
    if not isinstance(tools, list):
        raise ValueError
except Exception:
    print("FAIL\tMCP tools/list\t%s answered, but not with a tool list" % url)
    sys.exit(0)
if tools:
    print("PASS\tMCP tools/list\t%d tools listed by %s" % (len(tools), url))
else:
    print("FAIL\tMCP tools/list\t%s listed 0 tools" % url)
PY

# run_helper <fallback check name> <python source> <stdin text> [args…]
# A helper that crashes is an UNKNOWN for its check, never a silent pass.
run_helper() {
    local check="$1" source="$2" input="$3" out
    shift 3
    if out=$(printf '%s' "$input" | python3 -c "$source" "$@" 2>/dev/null); then
        emit <<EOF
$out
EOF
    else
        report UNKNOWN "$check" "the helper that reads this answer failed"
    fi
}

mcp_post() {
    curl -s -m "$TIMEOUT" -X POST "$MCP_URL" -H 'content-type: application/json' -d "$1" 2>/dev/null
}

is_hex() {
    case "$1" in
        ''|*[!0-9a-f]*) return 1 ;;
        *)              return 0 ;;
    esac
}

# ── What should be running ──────────────────────────────────────────────
EXPECTED=""
if ls_out=$(GIT_TERMINAL_PROMPT=0 git ls-remote origin refs/heads/main 2>/dev/null); then
    EXPECTED=$(printf '%s\n' "$ls_out" | awk 'NR == 1 { print $1 }')
fi
if ! is_hex "$EXPECTED"; then
    EXPECTED=""
fi

HEAD_SHA=""
if head_out=$(git rev-parse HEAD 2>/dev/null); then
    HEAD_SHA="$head_out"
fi
if ! is_hex "$HEAD_SHA"; then
    HEAD_SHA=""
fi

printf 'confirm-deploy (read-only)  controller %s\n' "$CONTROLLER_URL"
printf '  origin/main     %s\n' "${EXPECTED:-unreadable (git ls-remote origin refs/heads/main failed)}"
printf '  local checkout  %s\n\n' "${HEAD_SHA:-unreadable}"

# ── 1+2. The commit the controller and the workers report ───────────────
INFO_REPLY=""
if reply=$(mcp_post '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_platform_info","arguments":{}}}'); then
    INFO_REPLY="$reply"
fi
run_helper "controller commit" "$PY_BUILD" "$INFO_REPLY" "$EXPECTED" "$MCP_URL"

# ── 3+4. Containers ─────────────────────────────────────────────────────
DOCKER_OK=0
if docker info >/dev/null 2>&1; then
    DOCKER_OK=1
fi

CONTROLLER_STARTED=""

# container_check <check name> <container>; sets STARTED_AT when running.
container_check() {
    local state status rest started restarts
    STARTED_AT=""
    if [ "$DOCKER_OK" -ne 1 ]; then
        report UNKNOWN "$1" "the Docker daemon is not reachable"
        return 0
    fi
    if ! state=$(docker inspect -f '{{.State.Status}}|{{.State.StartedAt}}|{{.RestartCount}}' "$2" 2>/dev/null); then
        report FAIL "$1" "no container named $2"
        return 0
    fi
    status="${state%%|*}"
    rest="${state#*|}"
    started="${rest%%|*}"
    restarts="${rest#*|}"
    if [ "$status" = "running" ]; then
        STARTED_AT="$started"
        report PASS "$1" "$2 running since $started, restart count $restarts"
    else
        report FAIL "$1" "$2 is $status, not running"
    fi
    return 0
}

container_check "controller container" "$CONTROLLER"
CONTROLLER_STARTED="$STARTED_AT"
container_check "worker container" "$WORKER"

# ── 5. /health ──────────────────────────────────────────────────────────
# `-w` prints the status code on its own last line; curl prints 000 there
# when nothing answered, and exits non-zero, which `|| true` absorbs.
health_out=$(curl -s -m "$TIMEOUT" -w '\n%{http_code}' "$CONTROLLER_URL/health" 2>/dev/null || true)
health_code="${health_out##*$'\n'}"
health_body="${health_out%$'\n'*}"
health_status=$(printf '%s\n' "$health_body" | sed -n 's/.*"status"[[:space:]]*:[[:space:]]*"\([a-z_]*\)".*/\1/p')
if [ "$health_code" = "200" ] && [ "$health_status" = "ok" ]; then
    report PASS "controller health" "GET /health answered 200, status ok"
elif [ "$health_code" = "200" ]; then
    report FAIL "controller health" "GET /health answered 200 but status is '${health_status:-unreadable}', not ok"
elif [ "$health_code" = "000" ] || [ -z "$health_code" ]; then
    report FAIL "controller health" "GET $CONTROLLER_URL/health got no answer"
else
    report FAIL "controller health" "GET /health answered $health_code"
fi

# ── 6. Migrations ───────────────────────────────────────────────────────
# One SELECT, in a session Postgres itself holds read-only.
if [ "$DOCKER_OK" -ne 1 ]; then
    report UNKNOWN "migrations" "the Docker daemon is not reachable"
elif rows=$(docker exec -e PGOPTIONS='-c default_transaction_read_only=on' "$POSTGRES" \
        psql -U "$PG_USER" -d "$PG_DB" -At -v ON_ERROR_STOP=1 \
        -c 'SELECT version, success FROM _sqlx_migrations ORDER BY version' 2>/dev/null); then
    run_helper "migrations" "$PY_MIGRATIONS" "$rows" migrations "$HEAD_SHA" "$EXPECTED"
else
    report UNKNOWN "migrations" "could not read _sqlx_migrations through container $POSTGRES"
fi

# ── 7. ERROR lines since the controller started ─────────────────────────
if [ -z "$CONTROLLER_STARTED" ]; then
    report UNKNOWN "controller log" "the controller container is not running, so there is no log to read"
elif log_out=$(docker logs --since "$CONTROLLER_STARTED" "$CONTROLLER" 2>&1 \
        | python3 -c "$PY_LOG" "$CONTROLLER_STARTED" 2>/dev/null); then
    emit <<EOF
$log_out
EOF
else
    report UNKNOWN "controller log" "could not read the log of $CONTROLLER"
fi

# ── 8. MCP tools/list ───────────────────────────────────────────────────
TOOLS_REPLY=""
if reply=$(mcp_post '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'); then
    TOOLS_REPLY="$reply"
fi
run_helper "MCP tools/list" "$PY_TOOLS" "$TOOLS_REPLY" "$MCP_URL"

# ── Summary ─────────────────────────────────────────────────────────────
TOTAL=$((PASS_N + FAIL_N + UNKNOWN_N))
printf '\n'
if [ "$FAIL_N" -gt 0 ]; then
    printf '%sconfirm-deploy: %d checks — %d PASS, %d FAIL, %d UNKNOWN. Exit 1: a check FAILED.%s\n' \
        "$RED" "$TOTAL" "$PASS_N" "$FAIL_N" "$UNKNOWN_N" "$RST"
    exit 1
fi
if [ "$UNKNOWN_N" -gt 0 ]; then
    printf '%sconfirm-deploy: %d checks — %d PASS, 0 FAIL, %d UNKNOWN. Exit 0: UNKNOWN alone does not fail, and it is not a pass — those checks were not made.%s\n' \
        "$YEL" "$TOTAL" "$PASS_N" "$UNKNOWN_N" "$RST"
    exit 0
fi
printf '%sconfirm-deploy: %d checks — %d PASS, 0 FAIL, 0 UNKNOWN. Exit 0.%s\n' \
    "$GREEN" "$TOTAL" "$PASS_N" "$RST"
