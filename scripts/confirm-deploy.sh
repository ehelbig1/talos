#!/usr/bin/env bash
# `make confirm-deploy` — after `git pull && make up`: is the commit on
# origin/main the commit that is running, is the stack healthy, and did that
# commit pass its checks?
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
#   git rev-parse / merge-base / rev-list / diff / ls-tree / grep over LOCAL
#        objects, only when a process runs another commit than origin/main —
#        to tell whether the commits in between change anything that runs
#   docker info / docker inspect / docker logs
#   docker exec <postgres> psql … one SELECT, in a read-only session
#   GET  https://api.github.com/repos/<owner>/<repo>/commits/main — only when
#        `git ls-remote` fails and origin is on github.com; no credential
#   GET  https://api.github.com/repos/<owner>/<repo>/actions/workflows/
#        quality.yml/runs?head_sha=<origin/main> — when origin is on
#        github.com; no credential. And, only when that run did not pass,
#        GET …/actions/runs/<id>/jobs to name the jobs that failed
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
try:
    GAP = json.loads(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else {}
except Exception:
    GAP = {}


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


def gap_none(sha):
    g = GAP.get(sha)
    return isinstance(g, list) and g and g[0] == "none"


def describe_gap(sha):
    """The phrase for a running commit that is not origin/main."""
    g = GAP.get(sha)
    if not isinstance(g, list) or not g:
        return ""
    if g[0] == "none":
        return ("; the %s commit(s) between them change %s file(s), none of them built into "
                "the stack or mounted (documentation, CI, tests): no rebuild needed"
                % (g[1], g[2]))
    if g[0] == "some":
        files = clean(", ".join(g[3]) if len(g) > 3 else "", 200)
        if g[1] == 0:
            return "; deploy: %s" % files
        return ("; deploy: the %s commit(s) between them change files the stack is built "
                "or started from, or that this check cannot rule out (%s)" % (g[1], files))
    return "; whether a deploy would change anything is unknown: %s" % clean(g[1] if len(g) > 1 else "", 120)


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
        "running %s%s; origin/main could not be read (git ls-remote failed, and the GitHub API gave no commit)"
        % (sha, "-dirty" if dirty else ""))
elif not same_commit(sha, expected) and not dirty and gap_none(sha):
    out("PASS", "controller commit",
        "running %s, %s%s" % (sha, main, describe_gap(sha)))
elif not same_commit(sha, expected):
    out("FAIL", "controller commit",
        "running %s%s, but %s%s" % (sha, "-dirty" if dirty else "", main, describe_gap(sha)))
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
    elif expected and not same_commit(wsha, expected) and not (not wdirty and gap_none(wsha)):
        wrong.append(label)
    elif wdirty:
        dirty_rows.append(label)
    else:
        good.append(label)

basis = "self-reported at registration"
behind = sorted({split_build(w.get("build_version"))[0] for w in rows
                 if split_build(w.get("build_version"))[0]
                 and expected and not same_commit(split_build(w.get("build_version"))[0], expected)
                 and gap_none(split_build(w.get("build_version"))[0])})
if wrong:
    first = split_build(wrong[0].split("=", 1)[1])[0] if "=" in wrong[0] else None
    out("FAIL", "worker commit", "%d of %d registered worker row(s) report another commit than %s: %s (%s)%s"
        % (len(wrong), len(rows), main, ", ".join(wrong[:3]), basis, describe_gap(first) if first else ""))
elif not expected:
    out("UNKNOWN", "worker commit", "%d registered worker row(s) report %s; origin/main could not be read"
        % (len(rows), ", ".join((good + dirty_rows + unreadable)[:3])))
elif unreadable or dirty_rows:
    out("UNKNOWN", "worker commit", "%d of %d registered worker row(s) name no clean commit: %s (%s)"
        % (len(unreadable) + len(dirty_rows), len(rows), ", ".join((unreadable + dirty_rows)[:3]), basis))
else:
    note = ""
    if behind:
        note = "; %s is behind it by commits that change nothing that runs" % ", ".join(behind)
    out("PASS", "worker commit", "%d registered worker row(s) report %s (%s)%s%s"
        % (len(good), main, basis, note, "; the report was truncated" if fleet.get("truncated") else ""))
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

# stdin: the GitHub reply listing quality.yml runs for one commit.
# argv: <origin/main sha>
# Prints the verdict; for a run that did not pass it also prints
# "@<TAB><run id>", which the caller uses to ask which jobs failed.
read -r -d '' PY_CHECKS <<'PY' || true
import json, sys

sha = sys.argv[1]
short = sha[:7]
NAME = "checks on main"


def clean(s, limit=160):
    s = "".join(ch if ch.isprintable() else " " for ch in str(s))
    return s[:limit]


raw = sys.stdin.read()
if not raw.strip():
    print("UNKNOWN\t%s\tthe GitHub API gave no answer, so the result of quality.yml for %s was not read" % (NAME, short))
    sys.exit(0)
try:
    reply = json.loads(raw)
    runs = reply["workflow_runs"]
    if not isinstance(runs, list):
        raise ValueError
except Exception:
    why = ""
    try:
        why = ": %s" % clean(json.loads(raw).get("message", ""), 100)
    except Exception:
        pass
    print("UNKNOWN\t%s\tthe GitHub API did not list runs for %s%s" % (NAME, short, why))
    sys.exit(0)

# Only runs of exactly this commit count. The API was asked for them; a reply
# is not trusted to have honoured the filter.
runs = [r for r in runs if isinstance(r, dict) and r.get("head_sha") == sha]
if not runs:
    print("UNKNOWN\t%s\tno quality.yml run exists for %s (it has not started, or this commit "
          "reached main without one)" % (NAME, short))
    sys.exit(0)

runs.sort(key=lambda r: str(r.get("created_at", "")), reverse=True)
latest = runs[0]
event = clean(latest.get("event", "?"), 30)
earlier = ""
done = [r for r in runs[1:] if r.get("status") == "completed"]
if done:
    earlier = "; an earlier run of this commit concluded %s" % clean(done[0].get("conclusion"), 30)

if latest.get("status") != "completed":
    print("UNKNOWN\t%s\tquality.yml is %s for %s (%s run, started %s)%s"
          % (NAME, clean(latest.get("status"), 30), short, event, clean(latest.get("created_at"), 30), earlier))
elif latest.get("conclusion") == "success":
    print("PASS\t%s\tquality.yml passed for %s (%s run, finished %s)"
          % (NAME, short, event, clean(latest.get("updated_at"), 30)))
else:
    print("FAIL\t%s\tquality.yml concluded %s for %s (%s run, finished %s)%s"
          % (NAME, clean(latest.get("conclusion"), 30), short, event, clean(latest.get("updated_at"), 30), earlier))
    url = clean(latest.get("html_url", ""), 200)
    if url.startswith("https://github.com/"):
        print(">\t%s" % url)
    run_id = latest.get("id")
    if isinstance(run_id, int) and not isinstance(run_id, bool):
        print("@\t%d" % run_id)
PY

# stdin: the GitHub reply listing one run's jobs. Prints the jobs that did
# not pass, or nothing when the reply cannot be read.
read -r -d '' PY_JOBS <<'PY' || true
import json, sys

try:
    jobs = json.loads(sys.stdin.read())["jobs"]
    bad = [str(j.get("name", "?")) for j in jobs
           if isinstance(j, dict) and j.get("conclusion") not in ("success", "skipped", None)]
except Exception:
    sys.exit(0)
bad = ["".join(ch if ch.isprintable() else " " for ch in n)[:60] for n in bad]
if bad:
    more = "" if len(bad) <= 4 else " (+%d more)" % (len(bad) - 4)
    print(">\tdid not pass: %s%s" % ("; ".join(bad[:4]), more))
PY

# DOES THE GAP MATTER? argv: <origin/main sha> <running sha>…
# For each running commit that is not origin/main, says whether the commits
# between them change anything the running stack is built from or mounts.
# Prints one JSON object {running: [kind, …]}:
#   ["none", commits, files]           nothing that runs changed: no rebuild
#   ["some", commits, files, [paths]]  a built or mounted file changed
#   ["unknown", reason]                could not tell — treated as "some"
# Reads LOCAL git objects only (run after `git pull`); never fetches.
#
# A changed file is WITHOUT EFFECT only when all three hold:
#   1. it is under docs/, .github/, .githooks/ or scripts/tests/, under a
#      crate's tests/ directory, a lint or CI script (scripts/lint-*,
#      check-*, ci-*, ci_*, confirm-deploy.sh, dev-test-db.sh), or a .md
#      file. (`make up` runs scripts/preflight-disk.sh and
#      scripts/verify-observability.sh, which are not in this list, and any
#      change to the Makefile itself counts as changing what runs);
#   2. it is not under a directory an image copies or the compose file mounts
#      (RUNTIME_DIRS below — read from controller/Dockerfile, worker/Dockerfile
#      and docker-compose.yml on 2026-10-05);
#   3. nothing on origin/main can embed it: no Rust source names it as an
#      include would, and no build.rs, Dockerfile or compose file names it
#      outside a comment. Six documents under docs/ are compiled into the binaries with
#      include_str! (docs/workflow-engine/graph-json-schema.md, for one), so
#      "it is documentation" is not enough. An include always climbs out of
#      its crate, so its path names the file after a slash —
#      "../../docs/x.md" — and in Rust source the search is for "/docs/x.md"
#      (for a file inside a crate, "/" and its path within the crate). That
#      finds all six and not a prose mention such as "see CLAUDE.md".
# Anything else counts as changing what runs. A wrong "none" would hide a
# needed deploy, so every doubt falls on the other side.
read -r -d '' PY_GAP <<'PY' || true
import json, re, subprocess, sys

main, running = sys.argv[1], sys.argv[2:]
RUNTIME_DIRS = ("frontend/", "module-templates/", "workflow-templates/", "deploy/",
                "observability/", "docker/", "migrations/", "wit/", "talos_sdk_macros/",
                "scripts/dev-backup")
TOOLING = ("scripts/confirm-deploy.sh", "scripts/dev-test-db.sh")


def git(*args):
    r = subprocess.run(["git"] + list(args), capture_output=True, text=True)
    return r.returncode, r.stdout


def candidate(path):
    if path.startswith(RUNTIME_DIRS):
        return False
    return (path.startswith((".github/", ".githooks/", "docs/", "scripts/tests/"))
            or path.endswith(".md")
            or path in TOOLING
            or re.match(r"^scripts/(lint-|check-|ci-|ci_)", path) is not None
            or re.match(r"^[^/]+/tests/", path) is not None)


def named(main, needles, pathspecs, comment=None):
    """The needles that occur in `pathspecs` on `main`, or None on error.
    With `comment`, text from that marker to the end of a line is ignored."""
    if not needles:
        return set()
    args = ["grep", "-F", "-h"]
    for n in sorted(needles):
        args += ["-e", n]
    rc, out = git(*(args + [main, "--"] + pathspecs))
    if rc not in (0, 1):
        return None
    found = set()
    for line in out.split("\n"):
        if comment and comment in line:
            line = line[: line.index(comment)]
        found.update(n for n in needles if n in line)
    return found


result = {}
crates = None
rc, out = git("cat-file", "-e", main + "^{commit}")
main_ok = rc == 0
for run in running:
    if not main_ok:
        result[run] = ["unknown", "origin/main %s is not in this checkout; git pull first" % main[:7]]
        continue
    rc, out = git("rev-parse", "--verify", "-q", run + "^{commit}")
    full = out.strip()
    if rc != 0 or not re.fullmatch(r"[0-9a-f]{40}", full):
        result[run] = ["unknown", "the running commit %s is not in this checkout" % run]
        continue
    if full == main:
        result[run] = ["none", 0, 0]
        continue
    rc, _ = git("merge-base", "--is-ancestor", full, main)
    if rc != 0:
        result[run] = ["some", 0, 0, ["%s is not an ancestor of origin/main" % run]]
        continue
    rc, out = git("rev-list", "--count", "%s..%s" % (full, main))
    commits = int(out.strip()) if rc == 0 and out.strip().isdigit() else 0
    rc, out = git("diff", "--name-only", "--no-renames", full, main)
    if rc != 0:
        result[run] = ["unknown", "git diff failed"]
        continue
    files = [f for f in out.split("\n") if f]
    effect = [f for f in files if not candidate(f)]
    rest = [f for f in files if candidate(f)]
    if rest:
        if crates is None:
            rc, out = git("ls-tree", "-r", "--name-only", main)
            crates = {f.split("/")[0] for f in out.split("\n") if f.count("/") == 1 and f.endswith("/Cargo.toml")} if rc == 0 else None
        if crates is None:
            result[run] = ["unknown", "git ls-tree failed"]
            continue
        needle = {}
        for f in rest:
            first, _, inner = f.partition("/")
            needle[f] = inner if first in crates and inner else f
        in_rust = named(main, {"/" + n for n in needle.values()}, ["*.rs"])
        plain = set(needle.values()) | set(rest)
        in_build = named(main, plain, ["*build.rs"], "//")
        in_images = named(main, plain, ["*Dockerfile*", "*docker-compose*.yml"], "#")
        if in_rust is None or in_build is None or in_images is None:
            result[run] = ["unknown", "git grep failed"]
            continue
        in_build = in_build | in_images
        effect += [f for f in rest
                   if "/" + needle[f] in in_rust or needle[f] in in_build or f in in_build]
    if effect:
        result[run] = ["some", commits, len(files), sorted(effect)[:3] + (["…"] if len(effect) > 3 else [])]
    else:
        result[run] = ["none", commits, len(files)]
print(json.dumps(result))
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
EXPECTED_VIA=""
# <owner>/<repo> when origin is on github.com, else empty. Only a string of
# exactly that shape is ever put into a URL.
SLUG=""
if origin_url=$(git remote get-url origin 2>/dev/null); then
    SLUG=$(printf '%s\n' "$origin_url" \
        | sed -nE 's#^(git@github\.com:|ssh://git@github\.com/|https://github\.com/)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)$#\2#p' \
        | sed -E 's#\.git$##')
fi
if ! is_hex "$EXPECTED"; then
    EXPECTED=""
    # git could not ask: an SSH agent that is locked, or no route to the
    # remote. For a repository on github.com the same fact is one
    # unauthenticated GET away — the commit `main` points at is public for a
    # public repository, and a private one answers 404, which is not a commit
    # and leaves this UNKNOWN exactly as before. No credential is sent.
    slug="$SLUG"
    if [ -n "$slug" ]; then
        api_out=$(curl -s -m "$TIMEOUT" -H 'Accept: application/vnd.github.sha' \
            "https://api.github.com/repos/$slug/commits/main" 2>/dev/null || true)
        if [ "${#api_out}" -eq 40 ] && is_hex "$api_out"; then
            EXPECTED="$api_out"
            EXPECTED_VIA="  (from the GitHub API; git ls-remote origin failed)"
        fi
    fi
fi

HEAD_SHA=""
if head_out=$(git rev-parse HEAD 2>/dev/null); then
    HEAD_SHA="$head_out"
fi
if ! is_hex "$HEAD_SHA"; then
    HEAD_SHA=""
fi

printf 'confirm-deploy (read-only)  controller %s\n' "$CONTROLLER_URL"
printf '  origin/main     %s%s\n' "${EXPECTED:-unreadable (git ls-remote origin refs/heads/main failed, and the GitHub API gave no commit)}" "$EXPECTED_VIA"
printf '  local checkout  %s\n\n' "${HEAD_SHA:-unreadable}"

# ── 1+2. The commit the controller and the workers report ───────────────
INFO_REPLY=""
if reply=$(mcp_post '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_platform_info","arguments":{}}}'); then
    INFO_REPLY="$reply"
fi
# The builds the controller and its registered workers report that are not
# origin/main, and whether the commits between matter (PY_GAP).
GAP_JSON=""
if [ -n "$EXPECTED" ] && [ -n "$INFO_REPLY" ]; then
    behind_shas=$(printf '%s' "$INFO_REPLY" | python3 -c '
import json, re, sys
main = sys.argv[1]
try:
    info = json.loads(json.loads(sys.stdin.read())["result"]["content"][0]["text"])
except Exception:
    sys.exit(0)
builds = [info.get("build_version")]
fleet = info.get("fleet") if isinstance(info.get("fleet"), dict) else {}
builds += [w.get("build_version") for w in fleet.get("workers") or []
           if isinstance(w, dict) and w.get("source") == "registered"]
seen = set()
for b in builds:
    m = re.fullmatch(r".*\+([0-9a-f]{7,40})", b) if isinstance(b, str) else None
    if m and not main.startswith(m.group(1)) and m.group(1) not in seen:
        seen.add(m.group(1))
        print(m.group(1))
' "$EXPECTED" 2>/dev/null || true)
    if [ -n "$behind_shas" ]; then
        # shellcheck disable=SC2086 # one short hex commit per word, by construction
        GAP_JSON=$(python3 -c "$PY_GAP" "$EXPECTED" $behind_shas 2>/dev/null || true)
    fi
fi
run_helper "controller commit" "$PY_BUILD" "$INFO_REPLY" "$EXPECTED" "$MCP_URL" "$GAP_JSON"

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

# ── 9. Did the commit on main pass its checks ───────────────────────────
# quality.yml runs once for every commit that lands on main. A commit can be
# running and healthy and still be one whose tests failed.
if [ -z "$EXPECTED" ]; then
    report UNKNOWN "checks on main" "origin/main could not be read, so there is no commit to ask about"
elif [ -z "$SLUG" ]; then
    report UNKNOWN "checks on main" "origin is not a github.com repository, so its workflow runs were not read"
else
    runs_reply=$(curl -s -m "$TIMEOUT" -H 'Accept: application/vnd.github+json' \
        "https://api.github.com/repos/$SLUG/actions/workflows/quality.yml/runs?head_sha=$EXPECTED&per_page=20" 2>/dev/null || true)
    if checks_out=$(printf '%s' "$runs_reply" | python3 -c "$PY_CHECKS" "$EXPECTED" 2>/dev/null); then
        failed_run=$(printf '%s\n' "$checks_out" | awk -F '\t' '$1 == "@" { print $2; exit }')
        checks_out=$(printf '%s\n' "$checks_out" | awk -F '\t' '$1 != "@"')
        emit <<EOF
$checks_out
EOF
        case "$failed_run" in
            ''|*[!0-9]*) ;;
            *)
                jobs_reply=$(curl -s -m "$TIMEOUT" -H 'Accept: application/vnd.github+json' \
                    "https://api.github.com/repos/$SLUG/actions/runs/$failed_run/jobs?per_page=100" 2>/dev/null || true)
                if jobs_out=$(printf '%s' "$jobs_reply" | python3 -c "$PY_JOBS" 2>/dev/null) && [ -n "$jobs_out" ]; then
                    emit <<EOF
$jobs_out
EOF
                fi
                ;;
        esac
    else
        report UNKNOWN "checks on main" "the helper that reads this answer failed"
    fi
fi

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
