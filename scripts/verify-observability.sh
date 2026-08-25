#!/usr/bin/env bash
#
# Verify that the RUNNING dev Prometheus and Alertmanager are actually reading
# the files in this repo — i.e. that a merged, deployed config change is in
# effect. (Alertmanager joined in leg E; before that its LOADED config was
# compared by zero legs, which #666 named as its own largest residual.)
#
# WHY THIS EXISTS
# ---------------
# 2026-08-03. #625 merged, the worker was running the merged build, the alert
# it added was on disk, and `/api/v1/rules` still reported the pre-merge
# 13 groups / 37 rules with `WASMMetricsPipelineDead` absent. Nothing was
# broken in any way that any existing gate could see.
#
# Cause: the compose files bind-mounted the rule files and prometheus.yml as
# SINGLE FILES, and git replaces rather than rewrites a file in place. What
# was MEASURED: host file 21953 bytes, container serving a byte-exact
# 6464-byte prefix of that same current file, cut mid-word inside a comment.
# It parsed. The MECHANISM was then reproduced deterministically (Docker
# Desktop 29.6.2 / VirtioFS): once the host file is REPLACED — a new inode,
# which every git checkout of a changed file produces — the container's cached
# SIZE freezes at its last-known value, permanently, while the DATA path still
# resolves by name and returns the current bytes. Result: current content
# clamped to the superseded length. In-place edits (inode kept) track fine,
# which is why a same-length or in-place test "proves" the mount is healthy.
# "The mount pins the inode" is ruled out: the data came from the NEW file.
#
# The compose files now use DIRECTORY mounts, which resolve each child by name
# and were correct in every equivalent test — including on a four-day-old
# container. That is a large reduction, NOT a proof: one directory-mounted
# container was observed frozen and could not be made to repeat it. So the
# mount style removes the deterministic failure and THIS SCRIPT is the actual
# protection: it re-derives, from the LIVE container, whether what Prometheus
# is reading matches what is on disk, and fires on the symptom whatever the
# cause. Treat it as the gate, not as a belt-and-braces extra.
#
# WHY IT IS NOT IN lint-structural.sh
# -----------------------------------
# Structural lints run in CI, where no stack exists. A liveness check there
# could only skip when Prometheus is unreachable — and a check that skips in
# the environment it is supposed to gate is not a gate. Check 65's own header
# records that exact lesson. The STATIC half of this defect (never bind-mount
# a tracked config file singly) is enforced in lint-structural.sh as check 66,
# where it belongs and where it runs on every push. The LIVE half is here.
#
# WHY IT IS NOT IN scripts/smoke.sh
# ---------------------------------
# smoke.sh probes a DEPLOYED cluster via BASE_URL. Deployed Talos has no
# Prometheus of its own: docker-compose.prod.yml ships no prometheus service,
# and the chart delivers rules as a PrometheusRule CRD consumed by whatever
# Prometheus the operator already runs. There is nothing for smoke.sh to check.
#
# So: an opt-in target that FAILS LOUDLY when the stack is not up, rather than
# skipping, and that `make up` invokes once the stack is healthy — so it runs
# in the normal course of work without weakening CI.
#
# STATED LIMITS (overstating a gate is the same defect one level up):
#   * `make up` invokes this ADVISORY — it warns and continues, because a
#     stale Prometheus must not block a dev stack. Only `make
#     observability-verify` / `observability-reload` treat it as a hard gate.
#   * Requires python3 + PyYAML. Without PyYAML the ImportError fails the run
#     (loudly, but for the wrong reason — legs B/C never execute).
#   * Prometheus GLOBS rule_files. Leg C resolves each entry as a literal
#     path, so a glob entry is reported as unresolvable — a false positive,
#     the loud direction. Same limit as structural check 65(b).
#   * Leg B cannot verify a changed CREDENTIAL took effect (Prometheus
#     redacts/restructures those when it marshals its config — see
#     SECRET_KEYS below). Leg A still compares the raw file bytes.
#   * Leg E has the same limit for Alertmanager and closes it differently: an
#     inline credential is redacted identically on both sides, so instead of
#     comparing it, leg E FAILS on it — a credential literal in a tracked
#     config file is a containment violation in its own right. No byte of any
#     credential is read, hashed or printed anywhere in this script.
#
# Usage:
#   scripts/verify-observability.sh              # against 127.0.0.1:9090
#   PROM_URL=http://host:9090 scripts/verify-observability.sh
#
# Env:
#   PROM_URL        Prometheus base URL.      Default http://127.0.0.1:9090
#   PROM_CONTAINER  Container name to inspect. Default talos-prometheus
#
# Exit 0 = the running Prometheus and this repo agree. Non-zero = they do not.

set -uo pipefail

PROM_URL="${PROM_URL:-http://127.0.0.1:9090}"
PROM_CONTAINER="${PROM_CONTAINER:-talos-prometheus}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAIL=0

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

bold "▶ observability liveness: is the running stack reading THIS repo?"

# ── preflight: fail loudly, never skip ────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
    red "✗ docker not found — cannot inspect the running Prometheus."
    yellow "  → this target verifies a LIVE stack. Start it with 'make up'."
    exit 1
fi
if ! docker inspect "$PROM_CONTAINER" >/dev/null 2>&1; then
    red "✗ container '$PROM_CONTAINER' does not exist."
    yellow "  → this target verifies a LIVE stack and deliberately does NOT skip"
    yellow "    when the stack is down: a check that skips is not a gate."
    yellow "    Start the stack with 'make up', or set PROM_CONTAINER."
    exit 1
fi
if [ "$(docker inspect -f '{{.State.Running}}' "$PROM_CONTAINER")" != "true" ]; then
    red "✗ container '$PROM_CONTAINER' exists but is not running."
    exit 1
fi
if ! curl -fsS --max-time 10 "$PROM_URL/-/ready" >/dev/null 2>&1; then
    red "✗ Prometheus at $PROM_URL is not ready."
    yellow "  → the container is running but its HTTP API is unreachable."
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════════
# LEG A — every bind-mounted file the container reads must be byte-identical
#         to the file on disk.
#
# This is the general form of the defect and the one that would have caught
# it: it compares CONTENT, so it fires on the truncation signature regardless
# of which file, which service, or which mount style caused it. It is derived
# from the LIVE container's mounts, never from a hardcoded list — a hardcoded
# list is what rots (check 65's own lesson), and a third rule file added
# tomorrow is covered automatically.
# ══════════════════════════════════════════════════════════════════════════
bold "  A. mounted files match the host byte-for-byte"

MOUNTS="$(docker inspect "$PROM_CONTAINER" \
    --format '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}|{{.Destination}}|{{.RW}}{{"\n"}}{{end}}{{end}}')"

if [ -z "$(printf '%s' "$MOUNTS" | tr -d '[:space:]')" ]; then
    red "✗ '$PROM_CONTAINER' has no bind mounts at all — it cannot be reading this repo."
    FAIL=1
fi

checked=0
while IFS='|' read -r src dst rw; do
    [ -n "${src:-}" ] || continue
    # Docker Desktop reports macOS bind sources under /host_mnt.
    hostsrc="${src#/host_mnt}"
    [ -e "$hostsrc" ] || hostsrc="$src"

    if [ ! -e "$hostsrc" ]; then
        red "  ✗ mount source '$src' does not exist on this host"
        yellow "    → the container is reading a path this checkout does not provide."
        FAIL=1
        continue
    fi

    # A read-write mount of config is a separate hazard: check 65 validates
    # rule-file mount mode, but nothing validated the rest until now.
    if [ "$rw" = "true" ]; then
        red "  ✗ '$dst' is mounted READ-WRITE; Prometheus config must be :ro"
        FAIL=1
    fi

    # Build the list of (hostfile, containerfile) pairs this mount provides.
    if [ -f "$hostsrc" ]; then
        pairs="$hostsrc|$dst"
    else
        pairs="$(cd "$hostsrc" && find . -type f 2>/dev/null \
                 | sed "s|^\./|$hostsrc/=|" \
                 | awk -F= -v d="$dst" '{print $1$2"|"d"/"$2}')"
    fi

    while IFS='|' read -r hf cf; do
        [ -n "${hf:-}" ] || continue
        hsum="$(shasum -a 256 "$hf" 2>/dev/null | awk '{print $1}')"
        csum="$(docker exec "$PROM_CONTAINER" sha256sum "$cf" 2>/dev/null | awk '{print $1}')"
        checked=$((checked + 1))
        if [ -z "$csum" ]; then
            red "  ✗ container cannot read '$cf' (host: $hf)"
            FAIL=1
        elif [ "$hsum" != "$csum" ]; then
            hsz="$(wc -c < "$hf" | tr -d ' ')"
            csz="$(docker exec "$PROM_CONTAINER" stat -c '%s' "$cf" 2>/dev/null || echo '?')"
            red "  ✗ STALE: '$cf' differs from '$hf'"
            yellow "    host $hsz bytes / container $csz bytes"
            if [ "$csz" != "?" ] && [ "$hsz" -gt "$csz" ] 2>/dev/null \
               && head -c "$csz" "$hf" | docker exec -i "$PROM_CONTAINER" cmp -s - "$cf" 2>/dev/null; then
                yellow "    the container is serving a byte-exact PREFIX of the host file —"
                yellow "    the single-file-bind-mount truncation signature. Recreate the"
                yellow "    container (a restart is enough) and switch the mount to its"
                yellow "    parent DIRECTORY so this cannot recur."
            else
                yellow "    the running process is not reading what this checkout contains."
            fi
            FAIL=1
        fi
    done <<< "$pairs"
done <<< "$MOUNTS"
[ "$FAIL" -eq 0 ] && green "  ✓ $checked mounted file(s) identical to the host"

# ══════════════════════════════════════════════════════════════════════════
# LEG B — the config Prometheus LOADED matches prometheus.yml on disk.
#
# Leg A proves the bytes under the mount are right. This proves Prometheus
# actually re-read them: a correct mount plus a process that has not reloaded
# since the edit is still "merged, deployed, and not in effect".
# ══════════════════════════════════════════════════════════════════════════
bold "  B/C. loaded config and rules match this checkout"
# Implemented in Python because both comparisons must be SEMANTIC, not textual.
#
#  * /api/v1/status/config returns Prometheus's own MARSHALLED YAML — comments
#    stripped, quoting normalised, every unset field filled in with its
#    default. A byte-comparison against the repo file can therefore never
#    pass, so the honest test is "everything this repo SPECIFIES is in effect",
#    i.e. the on-disk config is a recursive subset of the loaded one. Defaults
#    Prometheus adds are fine; a value the repo sets and the process does not
#    have is not.
#  * The marshalled config also writes rule_files entries at column 0, which
#    broke a first cut of this leg that parsed them with awk (`^[^[:space:]]`
#    ended the block on the first entry, so it found zero rule files and
#    reported "no alert definitions on disk" — a check that fails for the
#    wrong reason is barely better than one that skips).
MOUNTS="$MOUNTS" PROM_URL="$PROM_URL" ROOT="$ROOT" PROM_CONTAINER="$PROM_CONTAINER" \
PROM_CMD="$(docker inspect "$PROM_CONTAINER" --format '{{json .Config.Cmd}}')" \
python3 - <<'PYEOF'
import json, os, re, subprocess, sys, urllib.request
import yaml

FAIL = 0
def red(m):    print("\033[31m%s\033[0m" % m)
def yellow(m): print("\033[33m%s\033[0m" % m)
def green(m):  print("\033[32m%s\033[0m" % m)

prom = os.environ["PROM_URL"]; root = os.environ["ROOT"]

def api(path):
    try:
        with urllib.request.urlopen(prom + "/api/v1" + path, timeout=10) as r:
            return json.load(r)["data"]
    except Exception as e:
        red("  \u2717 cannot read %s/api/v1%s: %s" % (prom, path, e))
        sys.exit(1)

# host<-container mount table, from the LIVE container (never a hardcoded list)
mounts = []
for line in os.environ["MOUNTS"].splitlines():
    if not line.strip():
        continue
    src, dst, rw = line.split("|")
    host = src[len("/host_mnt"):] if src.startswith("/host_mnt") and os.path.exists(src[len("/host_mnt"):]) else src
    mounts.append((host, dst))

def to_host(cpath):
    for host, dst in mounts:
        if cpath == dst:
            return host
        if cpath.startswith(dst.rstrip("/") + "/"):
            return os.path.join(host, cpath[len(dst.rstrip("/")) + 1:])
    return None

# ── B. every setting this repo specifies is actually in effect ────────────
# Resolve the config file the CONTAINER actually reads, through the same mount
# table legs A and C use — not a path hardcoded relative to this script. The
# two can differ: a git worktree has its own copy of prometheus.yml that no
# container mounts, and comparing the running process against a checkout that
# does not feed it is a category error that would report a false divergence.
cfg_arg = next((a.split("=", 1)[1] for a in
                (json.loads(os.environ.get("PROM_CMD", "[]")) or [])
                if a.startswith("--config.file=")), "/etc/prometheus/prometheus.yml")
cfg_host = to_host(cfg_arg)
if cfg_host is None or not os.path.isfile(cfg_host):
    red("  \u2717 the container's --config.file (%s) resolves to no host file" % cfg_arg)
    yellow("    \u2192 Prometheus is reading a config this checkout does not provide.")
    sys.exit(1)
if not os.path.realpath(cfg_host).startswith(os.path.realpath(root) + os.sep):
    yellow("  \u26a0 the running stack is fed by %s, not %s" % (cfg_host, root))
    yellow("    (checking the stack against ITS OWN source; a worktree's copy is not mounted)")

loaded = yaml.safe_load(api("/status/config")["yaml"])
disk   = yaml.safe_load(open(cfg_host).read())

# Prometheus REDACTS and RESTRUCTURES credential fields when it marshals its
# config (`bearer_token` is re-emitted as `authorization: {credentials:
# <secret>}`), so these can never compare equal and would make this leg fail
# forever on a healthy stack. A permanently-red gate trains you to ignore it,
# which is the same defect one level up. STATED LIMIT: leg B therefore cannot
# verify that a changed credential took effect; leg A still compares the raw
# file bytes, so a changed token is caught there.
SECRET_KEYS = {"bearer_token", "bearer_token_file", "password", "password_file",
               "credentials", "credentials_file", "authorization", "basic_auth",
               "oauth2", "tls_config", "proxy_connect_header"}

def subset(want, got, path=""):
    """Report every place `want` is not satisfied by `got`."""
    bad = []
    if isinstance(want, dict):
        if not isinstance(got, dict):
            return [(path, want, got)]
        for k, v in want.items():
            if k in SECRET_KEYS:
                continue
            if k not in got:
                bad.append((path + "/" + str(k), v, "<absent>"))
            else:
                bad += subset(v, got[k], path + "/" + str(k))
    elif isinstance(want, list):
        if not isinstance(got, list) or len(got) < len(want):
            return [(path, want, got)]
        for i, v in enumerate(want):
            bad += subset(v, got[i], "%s[%d]" % (path, i))
    else:
        if want != got:
            bad.append((path, want, got))
    return bad

# `subset` is ONE-DIRECTIONAL by construction, and it has to be: Prometheus
# marshals its config with every unset field filled in, so `loaded` is a proper
# superset of `disk` on a healthy stack and a symmetric diff would be
# permanently red. The cost is a real blind spot, MEASURED on a throwaway rig:
# add a scrape job, reload, then DELETE it from disk without reloading — the
# process keeps scraping a job this checkout no longer declares and leg B
# reports "every setting is in effect", printing its own count of 2 jobs
# against a file declaring 1. Leg A is green too, because the mounted bytes do
# match.
#
# Closed for the two lists Prometheus never adds to on its own — scrape job
# NAMES and `rule_files` entries. Both are wholly repo-authored, so an entry
# present in the process and absent from disk is unambiguous drift and cannot
# be a filled-in default. Everything else in the config stays one-directional
# and is named as a limit rather than left implied.
extra_cfg = []
for label, dl, ll in (
        ("scrape job",
         [j.get("job_name") for j in (disk.get("scrape_configs") or [])],
         [j.get("job_name") for j in (loaded.get("scrape_configs") or [])]),
        ("rule_files entry",
         list(disk.get("rule_files") or []),
         list(loaded.get("rule_files") or []))):
    for name in sorted(set(ll) - set(dl)):
        extra_cfg.append((label, name))
if extra_cfg:
    red("  \u2717 the running config has %d entr(y/ies) this checkout does not declare:"
        % len(extra_cfg))
    for label, name in extra_cfg:
        yellow("      %s %r" % (label, name))
    yellow("    \u2192 the process is still running a deleted setting. Prometheus never")
    yellow("      invents a scrape job or a rule_files entry, so this is drift, not a")
    yellow("      default. Apply with 'make observability-reload'.")
    FAIL = 1

diffs = subset(disk, loaded)
if diffs:
    red("  \u2717 settings in %s are NOT in effect:" % cfg_host)
    for p, w, g in diffs[:12]:
        yellow("      %s: repo=%r running=%r" % (p, w, g))
    if len(diffs) > 12:
        yellow("      ... and %d more" % (len(diffs) - 12))
    yellow("    \u2192 the process has not re-read %s. Apply with 'make observability-reload'." % cfg_host)
    FAIL = 1
elif not extra_cfg:
    green("  \u2713 every setting in %s is in effect, and nothing extra is loaded (%d scrape job(s))"
          % (cfg_host, len(loaded.get("scrape_configs") or [])))

# ── C. every rule GROUP and every RULE on disk is loaded, AND ITS WHOLE
#      DEFINITION MATCHES ────────────────────────────────────────────────
#
# WHY THIS DIFFS THE WHOLE OBJECT INSTEAD OF AN ENUMERATED SUBSET.
#
# This leg has now been wrong three times in one direction — each time by
# comparing LESS than the whole thing, and each time reporting green over the
# exact condition it was built to detect:
#
#   1. #625 — it did not exist. A merged rules file was never read at all;
#      the container served a truncated prefix and nothing noticed.
#   2. #645 — it compared alert NAME SETS. #644 had REWRITTEN
#      `TalosWorkerFleetBuildSkew`'s expr from a deleted series to a live one;
#      the name was in both sets, so the gate ticked while the process kept
#      evaluating the un-fireable expr. Fixed by comparing four named facets:
#      expr, `for`, labels, annotations.
#   3. #665 — it compared exactly those four, and #665's whole fix was a
#      FIFTH field, `keep_firing_for`. MEASURED an hour after that merge:
#      2 rules carrying it on disk, 0 in the running process, and this script
#      exited 0 saying "the running Prometheus is reading exactly what its
#      source checkout contains". `POST /-/reload` took it 0 -> 2.
#
# An allow-list of what to COMPARE fails SILENT: every field invented after
# the list was written is invisible, and this leg's green becomes
# indistinguishable from a real one. An allow-list of what to IGNORE fails
# LOUD: a field invented tomorrow is unrecognised, and unrecognised is
# reported rather than skipped.
#
# So: diff the whole group object and the whole rule object, subtract only the
# named runtime-state fields in VOLATILE_* (each justified where it is
# declared), and treat a field that is neither mapped nor named as a FINDING.
# Specifically —
#   * a field the REPO SETS that this leg cannot compare is a hard FAIL. That
#     is the #665 shape exactly, and it fires even for a field nobody has
#     taught this script about, which is the property the last two fixes
#     lacked.
#   * a field only the API reports is a hard FAIL when it holds a truthy value
#     (the process is running a setting nothing verified) and a WARNING when
#     it is empty/zero (a default the repo does not set, which cannot hide a
#     divergence). Stated so a Prometheus upgrade that adds a defaulted field
#     does not make this gate permanently red — a permanently-red gate trains
#     you to ignore it, which is this script's own header warning.
#
# EXPR COMPARISON REMAINS TWO-STAGE, and the second stage is the authority.
# `/api/v1/rules` returns Prometheus's own re-rendered PromQL, not the repo
# text. Measured differences on this stack, all pure formatting: newlines
# collapsed, `on()` -> `on ()`, `1.0` -> `1`, `[50h]` -> `[2d2h]`, and label
# matchers re-sorted alphabetically. A textual compare would be permanently
# red. Stage 1 is a cheap textual normalisation that agrees on 52 of 54 live
# rules; stage 2 hands every residual to `promtool promql format`, i.e.
# Prometheus's OWN parser and printer. Typical cost 0-2 `docker exec`s.
#
# WHAT IS NOW COMPARED THAT WAS NOT: `keep_firing_for`; rule GROUPS (their
# existence, their file assignment, `interval` — resolved against the global
# `evaluation_interval` when a group omits it — and `limit`); and RECORDING
# rules, which were filtered out entirely and which alerting exprs depend on.
#
# STATED LIMITS:
#   * If `promtool promql format --experimental` is unavailable (older
#     Prometheus, or the flag withdrawn), stage 2 cannot run. The leg reports
#     the stage-1 verdict and SAYS it is unadjudicated rather than silently
#     downgrading.
#   * Stage 1 can only produce false MISMATCHES, never false matches, for
#     formatting differences — and stage 2 resolves those. The one direction
#     it can miss alone is whitespace INSIDE a quoted label value
#     (`{job="a b"}` vs `{job="ab"}`); stage 2 catches that whenever it runs.
#   * Rules are keyed by (rule_files entry, group, kind, name). Prometheus
#     GLOBS rule_files, so a glob entry resolves to no host file and is
#     reported unresolvable — a false positive in the loud direction, the same
#     limit as structural check 65(b).
#   * This compares the rule DEFINITIONS. It cannot tell you an expr is
#     correct, only that the process is evaluating the one on disk.
entries = loaded.get("rule_files") or []
if not entries:
    red("  ✗ the running Prometheus has NO rule_files at all — no alert can fire")
    FAIL = 1

def _canon_num(m):
    f = float(m.group(0))
    return str(int(f)) if f == int(f) and abs(f) < 1e15 else repr(f)

def norm_expr(e):
    """Cheap stage-1 canonicalisation. Applied IDENTICALLY to both sides, so
    it need only be deterministic — not semantically faithful."""
    e = re.sub(r"\s+", " ", e or "").strip()
    e = re.sub(r"\s*([^\w\s])\s*", r"\1", e)
    return re.sub(r"\d+\.\d+(?:[eE][+-]?\d+)?", _canon_num, e)

_UNIT = {"ms": 0, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "y": 31536000}

def norm_for(v):
    """A duration is `30m` on disk and 1800 (seconds) from the API."""
    if v is None:
        return 0
    if isinstance(v, (int, float)):
        return int(v)
    return sum(int(n) * _UNIT[u] for n, u in re.findall(r"(\d+)(ms|[smhdwy])", str(v)))

PROM_CONTAINER = os.environ.get("PROM_CONTAINER", "talos-prometheus")

def _promtool(expr):
    try:
        p = subprocess.run(
            ["docker", "exec", PROM_CONTAINER, "promtool", "promql", "format",
             "--experimental", expr],
            capture_output=True, text=True, timeout=30)
        return p.stdout.strip() if p.returncode == 0 else None
    except Exception:
        return None

PROMTOOL_OK = _promtool("up") == "up"
_fmt_cache = {}

def canon(expr):
    """Stage 2: Prometheus's own formatter, memoised."""
    if expr not in _fmt_cache:
        _fmt_cache[expr] = _promtool(expr)
    return _fmt_cache[expr]

# ── the ignore-list: the ONLY subtraction from a whole-object diff ────────
# Every entry is a RUNTIME-STATE field — it describes what the evaluator has
# most recently DONE, not what the rule IS, so it can never carry a drift
# between disk and process. Anything not listed here is compared or reported.
VOLATILE_RULE_FIELDS = {
    "state":          "pending/firing/inactive; changes on its own every evaluation",
    "alerts":         "the currently-firing instances (2.x spelling)",
    "activeAlerts":   "the same list under the spelling other versions/clients use",
    "health":         "ok/err/unknown — the outcome of the last evaluation",
    "lastEvaluation": "wall-clock timestamp of the last evaluation",
    "evaluationTime": "duration of the last evaluation, in seconds",
}
VOLATILE_GROUP_FIELDS = {
    "lastEvaluation": "wall-clock timestamp of the group's last evaluation",
    "evaluationTime": "duration of the group's last evaluation, in seconds",
}

# rule-file key -> /api/v1/rules key. Everything here IS compared.
RULE_FILE_TO_API = {
    "expr":            "query",
    "for":             "duration",
    "keep_firing_for": "keepFiringFor",
    "labels":          "labels",
    "annotations":     "annotations",
}
GROUP_FILE_TO_API = {"interval": "interval", "limit": "limit"}
# Identity: carried in the comparison KEY, so compared by the missing/extra sets.
RULE_FILE_IDENTITY  = {"alert", "record"}
RULE_API_IDENTITY   = {"name", "type"}
GROUP_FILE_IDENTITY = {"name", "rules"}
GROUP_API_IDENTITY  = {"name", "file", "rules"}

# A group that omits `interval` inherits the global evaluation_interval, so
# "absent on disk" is NOT zero here — resolve it rather than skipping it.
GLOBAL_EVAL = norm_for((loaded.get("global") or {}).get("evaluation_interval")) or 60

disk_groups, disk_rules = {}, {}
for entry in entries:
    hf = to_host(entry)
    if hf is None or not os.path.isfile(hf):
        red("  ✗ rule_files entry %r resolves to no file through the container's mounts" % entry)
        yellow("    → Prometheus GLOBS rule_files, so this loads ZERO groups silently.")
        FAIL = 1
        continue
    doc = yaml.safe_load(open(hf).read()) or {}
    for g in doc.get("groups") or []:
        gname = g.get("name")
        disk_groups[(entry, gname)] = g
        for r in g.get("rules") or []:
            kind = "alerting" if r.get("alert") else "recording"
            k = (entry, gname, kind, r.get("alert") or r.get("record"))
            # Prometheus permits two rules with the same name in one group, and
            # a dict would silently keep only the last — comparing one of them
            # and reporting green over the other. Same shape as the bug this
            # leg exists for, so it is reported rather than collapsed.
            if k in disk_rules:
                red("  ✗ %r is defined twice in group %r of %s — this leg compares"
                    % (k[3], gname, entry))
                yellow("    only one of them. Give them distinct names.")
                FAIL = 1
            disk_rules[k] = r

live_groups, live_rules = {}, {}
for g in api("/rules")["groups"]:
    live_groups[(g.get("file"), g.get("name"))] = g
    for r in g.get("rules") or []:
        live_rules[(g.get("file"), g.get("name"), r.get("type"), r.get("name"))] = r

# API fields present but empty, hence unverifiable and merely reported.
unknown_empty = {}
# expr differences promtool could not adjudicate (stage 2 unavailable/failed).
UNADJ = []

def _diff(disk, live, f2a, disk_ident, api_ident, volatile, what):
    """Whole-object diff, minus the named volatile fields. Returns facets."""
    facets = []
    for k in sorted(set(disk) - set(f2a) - disk_ident):
        facets.append(("repo sets %r" % k, disk[k],
                       "<leg C has no comparator for this %s field>" % what))
    for fk, ak in f2a.items():
        dv, lv = disk.get(fk), live.get(ak)
        if fk == "expr":
            if norm_expr(dv) != norm_expr(lv):
                agreed = False
                if PROMTOOL_OK:
                    cd, cl = canon(dv or ""), canon(lv or "")
                    if cd is not None and cl is not None:
                        agreed = (cd == cl)
                    else:
                        UNADJ.append(1)
                else:
                    UNADJ.append(1)
                if not agreed:
                    facets.append(("expr", dv, lv))
        elif fk in ("for", "keep_firing_for", "interval"):
            want = norm_for(dv)
            if fk == "interval" and dv is None:
                want = GLOBAL_EVAL
            if want != norm_for(lv):
                facets.append((fk, dv if dv is not None else
                               ("<global %ds>" % GLOBAL_EVAL if fk == "interval" else None), lv))
        elif fk == "limit":
            if int(dv or 0) != int(lv or 0):
                facets.append((fk, dv, lv))
        elif fk == "annotations":
            d0, l0 = (dv or {}), (lv or {})
            if d0 != l0:
                ks = sorted(set(d0) ^ set(l0)) + sorted(k for k in set(d0) & set(l0) if d0[k] != l0[k])
                facets.append(("annotations", "differing key(s): " + ", ".join(ks), "<not printed>"))
        else:
            if (dv or {}) != (lv or {}):
                facets.append((fk, dv, lv))
    known = set(f2a.values()) | api_ident | set(volatile)
    for k in sorted(set(live) - known):
        if live[k]:
            facets.append(("running has %r" % k, "<nothing in this checkout maps to it>", live[k]))
        else:
            unknown_empty.setdefault(k, what)
    return facets

gmissing = sorted(set(disk_groups) - set(live_groups))
gextra   = sorted(set(live_groups) - set(disk_groups))
gdrifted = []
for key in sorted(set(disk_groups) & set(live_groups)):
    f = _diff(disk_groups[key], live_groups[key], GROUP_FILE_TO_API,
              GROUP_FILE_IDENTITY, GROUP_API_IDENTITY, VOLATILE_GROUP_FIELDS, "rule-group")
    if f:
        gdrifted.append((key, f))

missing = sorted(set(disk_rules) - set(live_rules))
extra   = sorted(set(live_rules) - set(disk_rules))
drifted = []
for key in sorted(set(disk_rules) & set(live_rules)):
    f = _diff(disk_rules[key], live_rules[key], RULE_FILE_TO_API,
              RULE_FILE_IDENTITY, RULE_API_IDENTITY, VOLATILE_RULE_FIELDS, "rule")
    if f:
        drifted.append((key, f))

def _rk(k):
    return "%s [%s in %s of %s]" % (k[3], k[2], k[1], k[0])

if gmissing:
    red("  ✗ rule GROUPS on disk that the running Prometheus has not loaded:")
    for e, n in gmissing:
        yellow("      %s (in %s)" % (n, e))
    FAIL = 1
if gextra:
    red("  ✗ rule GROUPS the process is running that are not on disk:")
    for e, n in gextra:
        yellow("      %s (claiming %s)" % (n, e))
    FAIL = 1
if gdrifted:
    red("  ✗ rule GROUPS loaded under the right name with a DIFFERENT definition:")
    for (e, n), facets in gdrifted:
        for facet, want, got in facets:
            yellow("      %s (%s) — %s: repo=%r running=%r" % (n, e, facet, want, got))
    FAIL = 1

if missing:
    red("  ✗ defined on disk but NOT loaded by the running Prometheus:")
    for k in missing:
        yellow("      " + _rk(k))
    yellow("    → this is the '#625 merged and never took effect' symptom exactly.")
    FAIL = 1
if extra:
    red("  ✗ loaded by Prometheus but NOT defined on disk:")
    for k in extra:
        yellow("      " + _rk(k))
    yellow("    → the process is running rules this checkout does not contain.")
    FAIL = 1
if drifted:
    red("  ✗ loaded under the right NAME but with a DIFFERENT definition:")
    for k, facets in drifted:
        yellow("      %s — %s differs" % (_rk(k), ", ".join(f[0] for f in facets)))
        for facet, want, got in facets:
            yellow("        %s: repo=%r running=%r" % (facet, want, got))
    yellow("    → the process is evaluating a STALE definition of a rule that")
    yellow("      still exists by name — a name-only check cannot see this, and")
    yellow("      neither could the four-facet check this replaced.")
    yellow("      Apply with 'make observability-reload'.")
    if any(f[0].startswith(("repo sets ", "running has "))
           for _, fs in drifted for f in fs):
        yellow("    → a \'repo sets\'/\'running has\' line means the FIELD ITSELF is")
        yellow("      unknown to this leg. Teach it a comparator in RULE_FILE_TO_API,")
        yellow("      or name it in VOLATILE_RULE_FIELDS with the reason it cannot")
        yellow("      carry a drift. It is reported rather than skipped precisely so")
        yellow("      that the next field added to these files cannot repeat #665.")
    FAIL = 1
if UNADJ:
    yellow("    ⚠ %d expr difference(s) above are UNADJUDICATED: 'promtool promql"
           % len(UNADJ))
    yellow("      format --experimental' %s in %s, so stage 2 could not run."
           % ("is unavailable" if not PROMTOOL_OK else "failed on one side",
              PROM_CONTAINER))
    yellow("      They may be pure formatting — compare by hand before treating")
    yellow("      them as drift.")
if unknown_empty:
    yellow("    ⚠ the API reports %d field(s) this leg does not map, all empty on"
           % len(unknown_empty))
    yellow("      every object, so none can be hiding a divergence today:")
    for k, what in sorted(unknown_empty.items()):
        yellow("        %s (%s)" % (k, what))
    yellow("      Map or ignore-list them before this checkout starts setting them;")
    yellow("      a non-empty one FAILS this leg rather than being skipped.")

if disk_rules and not (missing or extra or drifted or gmissing or gextra or gdrifted):
    green("  ✓ %d group(s) and %d rule(s) on disk are loaded with matching whole-object"
          % (len(disk_groups), len(disk_rules)))
    green("    definitions (%d rule field(s) + %d group field(s) compared; %d named"
          % (len(RULE_FILE_TO_API), len(GROUP_FILE_TO_API), len(VOLATILE_RULE_FIELDS)))
    green("    runtime-state field(s) ignored)%s"
          % ("" if PROMTOOL_OK else " — expr compared textually only"))
elif not disk_rules:
    red("  ✗ found no rule definitions on disk — cannot verify anything")
    FAIL = 1

sys.exit(1 if FAIL else 0)
PYEOF
[ $? -ne 0 ] && FAIL=1

# ══════════════════════════════════════════════════════════════════════════
# LEG D — alert DELIVERY: the transport, and the credential containment.
#
# Legs A-C prove Prometheus is evaluating the right rules. They say nothing
# about whether a firing alert reaches anyone, which until 2026-08-18 it did
# not: 54 rules evaluated and the `alerting:` block was commented out.
#
# This leg checks the four things that are invisible statically:
#   D1. the transport EXISTS and is ready;
#   D2. the credential source does NOT resolve inside a checkout;
#   D3. no config mount is read-write, and secrets are not world-readable;
#   D4. the UI is bound to loopback ONLY;
#   D5. every credential file the RUNNING config names is PRESENT and
#       WELL-FORMED (and nothing is sitting there under a name it will
#       never read);
#   D6. the credential is ACCEPTED — passively from Alertmanager's own
#       delivery counters, and on request by sending one real alert.
#
# D5 and D6 exist because enabling delivery is "drop a file and reload", and
# until 2026-08-19 the only way to find out you had done it wrong was the
# first incident. Counting files in a directory is not checking them: this
# leg reported `1 credential file present, mode-checked` for a directory
# containing a file Alertmanager would never open.
#
# D4 is the one that matters most and the one a lint cannot do. Alertmanager's
# /api/v2/silences lets any caller silence every detector in this system, and
# Alertmanager ships no authentication. A published port bypasses the host
# firewall, and docker-compose.override.yml is gitignored and scanned by no
# lint — so the LIVE binding is the only trustworthy answer.
#
# STATED LIMITS:
#   * CONTENTS: D5 reads the FIRST LINE of a URL-typed credential far enough
#     to classify it into one of five fixed verdicts (ok / empty / insecure /
#     notaurl / dirty). No byte of a credential is ever printed, logged,
#     hashed, or included in any message — only the verdict word and the
#     file's basename. This is a deliberate, narrow widening of the older
#     "contents are never read" rule, stated here rather than done quietly;
#     everything else (mode, existence) is still metadata only.
#   * WELL-FORMED IS NOT VALID. A revoked Slack webhook is a perfectly-shaped
#     https:// URL. D5 cannot distinguish them; only a send can, which is
#     what D6 is for.
#   * D6's PASSIVE half reports on notifications ALREADY attempted since this
#     Alertmanager started. On a freshly-enabled stack that count is 0, and 0
#     failures out of 0 attempts is not evidence — it says so, and points at
#     the active probe rather than printing a green.
#   * D5 fails an `http://` credential URL with NO opt-out. A webhook URL with
#     a token in it IS the credential (alertmanager.yml says so), so plaintext
#     leaks it to anything on the path. An operator who deliberately points the
#     generic `url_file` receiver at an internal plaintext endpoint will fail
#     this leg and there is no flag to silence it — stated here so it is a
#     known cost rather than a surprise.
#   * D5 classifies only the FIRST LINE. A credential file with a valid first
#     line and junk on line two passes; Alertmanager itself trims only trailing
#     whitespace, so such a file would also break at notify time. Rare enough to
#     leave, loud enough to name.
#   * D6's ACTIVE half (TALOS_ALERT_SEND_TEST=1) proves the ENDPOINT ACCEPTED
#     the POST. It does not prove a human saw it: a valid webhook for an
#     archived channel, or one nobody has muted-checked, accepts happily.
#     That last link is not testable from here — see B4 in the change notes.
#   * Containment resolves symlinks and checks BOTH checkout roots (this one
#     and, via `git rev-parse --git-common-dir`, the main working tree). In
#     this repo's layout a worktree's own root is NOT an ancestor of the main
#     clone, so checking one root would accept a key file sitting in the
#     other — the #641 two-root fix, reused here.
#   * If the checkout FEEDING the running stack declares no alertmanager
#     service, this leg reports and skips rather than failing: that is the
#     worktree case (the stack mounts main), and failing there would be a red
#     that says nothing about the tree being verified. It prints which
#     checkout it looked at, exactly as leg B does — a check that redirects
#     must SAY so.
# ══════════════════════════════════════════════════════════════════════════
bold "  D. alert delivery: transport, binding, credential containment + acceptance"

AM_CONTAINER="${AM_CONTAINER:-talos-alertmanager}"
AM_URL="${AM_URL:-http://127.0.0.1:9093}"

# Classify one credential file's first line. Echoes exactly ONE fixed word and
# nothing derived from the content. Callers must never echo $line — it does not
# leave this function.
_cred_shape() {
    local f="$1" key="$2" line
    line="$(head -c 4096 "$f" 2>/dev/null | head -n 1)"
    [ -n "$line" ] || { printf 'empty'; return; }
    case "$key" in
        *url*_file)
            case "$line" in
                https://*) ;;
                http://*)  printf 'insecure'; return ;;
                *)         printf 'notaurl';  return ;;
            esac
            # A pasted `curl -X POST <url>`, a quoted value, or a stray CR.
            case "$line" in
                *[[:space:]]*|*'"'*|*"'"*|*'<'*) printf 'dirty'; return ;;
            esac
            printf 'ok' ;;
        *)
            # Opaque credential (token, routing key). Shape unknown by design;
            # only whitespace/quote contamination is checkable.
            case "$line" in
                *[[:space:]]*|*'"'*|*"'"*) printf 'opaque_dirty'; return ;;
            esac
            printf 'opaque_ok' ;;
    esac
}

# Sum every sample of a Prometheus metric family in $AM_METRICS.
_amsum() {
    printf '%s' "$AM_METRICS" | awk -v m="$1" '
        $0 !~ /^#/ && index($0, m) == 1 { s += $NF } END { printf "%d", s + 0 }'
}

# Which checkout feeds the RUNNING stack? Derived from the live Prometheus
# config mount, never from this script's own location.
STACK_ROOT=""
while IFS='|' read -r src dst _rw; do
    [ -n "${src:-}" ] || continue
    hostsrc="${src#/host_mnt}"
    [ -e "$hostsrc" ] || hostsrc="$src"
    case "$hostsrc" in
        */observability/prometheus) STACK_ROOT="${hostsrc%/observability/prometheus}" ;;
    esac
done <<< "$MOUNTS"
[ -n "$STACK_ROOT" ] || STACK_ROOT="$ROOT"

if ! grep -qE '^[[:space:]]{2}alertmanager:[[:space:]]*$' "$STACK_ROOT/docker-compose.yml" 2>/dev/null; then
    yellow "  ⚠ $STACK_ROOT/docker-compose.yml declares no alertmanager service —"
    yellow "    alert delivery is not configured in the checkout that feeds this stack."
    if grep -qE '^[[:space:]]{2}alertmanager:[[:space:]]*$' "$ROOT/docker-compose.yml" 2>/dev/null; then
        yellow "    (THIS checkout ($ROOT) does declare one. The running stack is fed by"
        yellow "     another tree, so leg D cannot exercise your change — stand up a"
        yellow "     throwaway stack from this checkout to verify it.)"
    fi
elif ! docker inspect "$AM_CONTAINER" >/dev/null 2>&1; then
    red "  ✗ '$STACK_ROOT/docker-compose.yml' declares an alertmanager service but"
    red "    container '$AM_CONTAINER' does not exist — every alert is undelivered."
    yellow "    → docker compose up -d alertmanager"
    FAIL=1
elif [ "$(docker inspect -f '{{.State.Running}}' "$AM_CONTAINER")" != "true" ]; then
    red "  ✗ '$AM_CONTAINER' exists but is not running — every alert is undelivered."
    FAIL=1
else
    D_FAIL=0

    # ── D1. ready ────────────────────────────────────────────────────────
    if ! curl -fsS --max-time 10 "$AM_URL/-/ready" >/dev/null 2>&1; then
        red "  ✗ Alertmanager is running but $AM_URL/-/ready is unreachable"
        D_FAIL=1
    fi

    # ── D4. loopback ONLY ────────────────────────────────────────────────
    # `docker inspect` reports every published binding; an empty or 0.0.0.0
    # HostIp means "all interfaces", which puts the silence API on the LAN.
    while IFS= read -r hostip; do
        [ -n "$hostip" ] || continue
        case "$hostip" in
            127.0.0.1|::1) ;;
            *)  red "  ✗ Alertmanager is published on HostIp '$hostip', not loopback"
                yellow "    → its /api/v2/silences can disable EVERY detector in this system and"
                yellow "      it has no authentication of its own. Bind it 127.0.0.1:9093:9093."
                yellow "      Check docker-compose.override.yml too — it is gitignored and no"
                yellow "      lint scans it."
                D_FAIL=1 ;;
        esac
    done <<< "$(docker inspect "$AM_CONTAINER" \
        --format '{{range $p, $c := .NetworkSettings.Ports}}{{range $c}}{{.HostIp}}{{"\n"}}{{end}}{{end}}')"

    # ── D2/D3. mounts: containment, mode, permissions ────────────────────
    # Containment roots: this checkout AND the main working tree. A worktree
    # root is not an ancestor of the main clone, so one root is not enough.
    ROOTS="$(cd "$ROOT" && pwd -P)"
    [ "$STACK_ROOT" != "$ROOT" ] && ROOTS="$ROOTS
$(cd "$STACK_ROOT" && pwd -P 2>/dev/null || true)"
    _common="$(cd "$ROOT" && git rev-parse --git-common-dir 2>/dev/null || true)"
    if [ -n "$_common" ]; then
        _main="$( (cd "$ROOT" && cd "$_common/.." && pwd -P) 2>/dev/null || true)"
        [ -n "$_main" ] && ROOTS="$ROOTS
$_main"
    fi
    # Dedupe: a worktree and the main clone can resolve to the same string,
    # and reporting one violation twice reads as two problems.
    ROOTS="$(printf '%s\n' "$ROOTS" | sort -u)"

    while IFS='|' read -r src dst rw; do
        [ -n "${src:-}" ] || continue
        hostsrc="${src#/host_mnt}"
        [ -e "$hostsrc" ] || hostsrc="$src"

        if [ "$rw" = "true" ]; then
            red "  ✗ Alertmanager mounts '$dst' READ-WRITE; config and secrets must be :ro"
            D_FAIL=1
        fi

        case "$dst" in
            */secrets*)
                real="$( (cd "$hostsrc" 2>/dev/null && pwd -P) || printf '%s' "$hostsrc")"
                # Handed to D5, which needs both ends of the mapping to turn a
                # container path from the running config into a host path.
                SECRETS_REAL="$real"
                SECRETS_DST="$dst"
                while IFS= read -r r; do
                    [ -n "$r" ] || continue
                    if [ "$real" = "$r" ] || case "$real" in "$r"/*) true ;; *) false ;; esac; then
                        red "  ✗ the credential mount resolves INSIDE a checkout: $real"
                        yellow "    → (within $r). A secret must never live where git can commit it,"
                        yellow "      and symlinks are resolved before this comparison. Move it out"
                        yellow "      and point TALOS_ALERT_SECRETS_DIR at it."
                        D_FAIL=1
                    fi
                done <<< "$ROOTS"
                # Presence and permissions only — contents are never read.
                if [ -d "$real" ]; then
                    n=0
                    bad_mode=0
                    for f in "$real"/*; do
                        [ -f "$f" ] || continue
                        n=$((n + 1))
                        mode="$(stat -f '%Lp' "$f" 2>/dev/null || stat -c '%a' "$f" 2>/dev/null || echo '')"
                        case "$mode" in
                            ''|600|400) ;;
                            *) red "  ✗ credential file mode $mode (name only: $(basename "$f")) — chmod 600"
                               bad_mode=1
                               D_FAIL=1 ;;
                        esac
                    done
                    # NO presence verdict here, deliberately. `$n` is a COUNT
                    # of whatever happens to be in the directory, and a count
                    # cannot tell a credential Alertmanager will read from one
                    # it will not — this line used to print
                    # "1 credential file present, mode-checked" over a
                    # directory holding a file named from
                    # deploy/observability/alertmanager-route.yaml that the dev
                    # config never opens. D5 owns presence, because D5 asks the
                    # running process which files it actually wants.
                    if [ "$n" -gt 0 ] && [ "$bad_mode" -eq 0 ]; then
                        green "  ✓ $n file(s) in the credential dir, all mode 600/400"
                    fi
                fi
                ;;
        esac
    done <<< "$(docker inspect "$AM_CONTAINER" \
        --format '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}|{{.Destination}}|{{.RW}}{{"\n"}}{{end}}{{end}}')"

    # ── D5. is the credential PRESENT, and WELL-FORMED, for the files this
    #        Alertmanager will ACTUALLY open? ──────────────────────────────
    #
    # THE REQUIRED LIST IS DERIVED FROM THE RUNNING PROCESS, NEVER FROM
    # alertmanager.yml ON DISK. That file documents four receiver OPTIONS in
    # COMMENTS — webhook_url_file, bot_token_file, auth_password_file, a
    # commented http_headers.files — and grep cannot tell an option from a
    # requirement. A check built on grep would demand credential files for
    # receivers that do not ship: the #644 defect (a commented line read as
    # what the product does) reproduced inside a gate written to prevent that
    # class. `/api/v2/status` returns the config as Alertmanager PARSED it,
    # comments stripped — measured 2357 bytes against ~11 KB on disk, with only
    # the two live `*_file` entries present.
    #
    # It also catches the opposite error, which the old file-count could not:
    # a credential dropped under a name nothing reads. That is not exotic —
    # deploy/observability/alertmanager-route.yaml, the fragment an operator is
    # most likely to copy from, names FOUR different filenames
    # (slack-webhook-default, slack-webhook-oncall, pagerduty-routing-key,
    # jira-ops-hygiene-webhook), none of which the dev config opens.
    # -1 = D5 could not determine it. 0 = nothing configured (the INERT
    # shipping state). >0 = the operator has enabled at least one receiver.
    # D6 needs this to tell "inert by design" from "believed working, broken":
    # the failure counter looks identical in both, and calling the first one RED
    # would leave `make observability-verify` permanently red on a stack that is
    # in exactly the state #646 shipped — which trains an operator to ignore
    # red, the defect this whole arc is about.
    _cred_present=-1
    if [ -n "${SECRETS_DST:-}" ]; then
        _named="$(curl -fsS --max-time 10 "$AM_URL/api/v2/status" 2>/dev/null | python3 -c '
import json, re, sys
try:
    cfg = json.load(sys.stdin)["config"]["original"]
except Exception:
    sys.exit(0)
seen = set()
for k, v in re.findall(r"^\s*([A-Za-z0-9_]+_file):\s*\"?([^\"\s#]+)\"?\s*$", cfg, re.M):
    if (k, v) not in seen:
        seen.add((k, v))
        print(k + "\t" + v)
' 2>/dev/null || true)"

        if [ -z "$_named" ]; then
            yellow "  ⚠ could not read the running config from $AM_URL/api/v2/status —"
            yellow "    D5 (credential present + well-formed) did NOT run. This is a gap,"
            yellow "    not a pass: nothing below has checked your credential."
        else
            _want=0
            _cred_present=0
            _wanted_names=""
            while IFS="$(printf '\t')" read -r _key _cpath; do
                [ -n "${_cpath:-}" ] || continue
                case "$_cpath" in "$SECRETS_DST"/*) ;; *) continue ;; esac
                _want=$((_want + 1))
                _base="${_cpath##*/}"
                _wanted_names="$_wanted_names $_base"
                _hpath="$SECRETS_REAL/$_base"

                if [ ! -f "$_hpath" ]; then
                    yellow "  ⚠ $_key names $_base — NOT PRESENT. Delivery through that"
                    yellow "    receiver is INERT: Alertmanager reads it at NOTIFY time, so it"
                    yellow "    started and loaded cleanly and will fail every send silently."
                    yellow "    → printf '%s' \"\$URL\" > $SECRETS_REAL/$_base && chmod 600 \"\$_\""
                    yellow "      then: make observability-reload"
                    continue
                fi

                _cred_present=$((_cred_present + 1))
                case "$(_cred_shape "$_hpath" "$_key")" in
                    ok|opaque_ok)
                        green "  ✓ $_base present and well-formed for $_key" ;;
                    empty)
                        red   "  ✗ $_base is EMPTY (0 bytes of content). A touch/redirect that"
                        red   "    lost its input looks identical to a configured credential."
                        D_FAIL=1 ;;
                    insecure)
                        red   "  ✗ $_base is an http:// URL — a credential-bearing webhook must"
                        red   "    be https://. (Value not shown.)"
                        D_FAIL=1 ;;
                    notaurl)
                        red   "  ✗ $_base does not begin with a URL scheme, but $_key is a"
                        red   "    URL-typed field. (Value not shown.)"
                        D_FAIL=1 ;;
                    dirty|opaque_dirty)
                        red   "  ✗ $_base contains whitespace or quote characters on its first"
                        red   "    line — the usual cause is pasting a whole curl command, or"
                        red   "    \"quoting\" the value. Alertmanager trims only trailing"
                        red   "    whitespace. (Value not shown.)"
                        D_FAIL=1 ;;
                esac
            done <<< "$_named"

            if [ "$_want" -eq 0 ]; then
                yellow "  ⚠ the running config names no credential file under $SECRETS_DST —"
                yellow "    no receiver reads a secret, so nothing here can be checked."
            fi

            # Files present that nothing will ever open. Basenames only.
            if [ -d "$SECRETS_REAL" ]; then
                for _f in "$SECRETS_REAL"/*; do
                    [ -f "$_f" ] || continue
                    _b="${_f##*/}"
                    case " $_wanted_names " in
                        *" $_b "*) ;;
                        *) yellow "  ⚠ $_b is in the credential dir but the running config never"
                           yellow "    names it — Alertmanager will not open it. Check the filename"
                           yellow "    against api_url_file/url_file in the config; note that"
                           yellow "    deploy/observability/alertmanager-route.yaml is a"
                           yellow "    DOCUMENTATION FRAGMENT using different names." ;;
                    esac
                done
            fi
        fi
    fi

    # ── D6. is the credential ACCEPTED? ───────────────────────────────────
    # Present and well-formed is not delivered. A revoked Slack webhook is a
    # perfectly-shaped https:// URL, and D5 passes it.
    AM_METRICS="$(curl -fsS --max-time 10 "$AM_URL/metrics" 2>/dev/null || true)"
    if [ -z "$AM_METRICS" ]; then
        yellow "  ⚠ could not scrape $AM_URL/metrics — D6 (acceptance) did NOT run."
    else
        _reload="$(printf '%s' "$AM_METRICS" \
            | awk '$1 == "alertmanager_config_last_reload_successful" { print $2 }')"
        if [ "${_reload:-1}" = "0" ]; then
            red "  ✗ Alertmanager's LAST CONFIG RELOAD FAILED — it is still serving the"
            red "    previous config, so an edit you believe is live is not."
            yellow "    → docker logs $AM_CONTAINER | tail -30"
            D_FAIL=1
        fi

        _sent="$(_amsum alertmanager_notifications_total)"
        _failed="$(_amsum alertmanager_notifications_failed_total)"
        _req="$(_amsum alertmanager_notification_requests_total)"
        _reqfail="$(_amsum alertmanager_notification_requests_failed_total)"
        _reqok=$(( _req - _reqfail ))

        # "0 failed" IS NOT "delivered". alertmanager_notifications_failed_total
        # counts only a notification Alertmanager has GIVEN UP on. While it is
        # still retrying an endpoint that rejects every request, that counter
        # reads 0 and notifications_total reads 1 — so the obvious pair prints a
        # green over a dead endpoint. MEASURED against an unresolvable host:
        # requests_total=6, requests_FAILED_total=6, notifications_failed_total=0,
        # notifications_total=1. The first version of this block printed
        # "✓ 1 notification(s) attempted, 0 failed" for exactly that.
        #
        # So the delivered question is answered by SUCCESSFUL REQUESTS
        # (requests_total - requests_failed_total), and the given-up counter is
        # reported beside it rather than used as the verdict.
        _broken=0
        [ "$_failed" -gt 0 ] && _broken=1
        [ "$_req" -gt 0 ] && [ "$_reqok" -eq 0 ] && _broken=1

        if [ "$_broken" -eq 1 ] && [ "$_cred_present" -eq 0 ]; then
            # INERT BY DESIGN, not broken. Every send fails because no
            # credential is configured, which is the state #646 shipped
            # deliberately. Reporting it RED would make this target
            # permanently red out of the box.
            yellow "  ⚠ $_reqfail notification request(s) have failed ($_failed given up on),"
            yellow "    and NO credential is configured"
            yellow "    — so this is the documented INERT state, not a fault. Every alert"
            yellow "    since this Alertmanager started has reached nobody. Enable delivery"
            yellow "    by creating the file(s) named above; TalosAlertDeliveryFailing is"
            yellow "    firing about exactly this, through the channel that does not work."
        elif [ "$_broken" -eq 1 ]; then
            red "  ✗ delivery is FAILING and a credential IS configured:"
            red "    $_req notification request(s) attempted, $_reqok succeeded,"
            red "    $_reqfail failed, $_failed notification(s) given up on."
            red "    Alerts routed through that receiver are reaching NOBODY while"
            red "    the configuration looks enabled."
            printf '%s' "$AM_METRICS" \
                | awk '$0 !~ /^#/ && index($0,"alertmanager_notifications_failed_total")==1 && $NF+0 > 0 { print "      " $0 }'
            yellow "    reason=\"other\" is typically a missing/unreadable credential FILE;"
            yellow "    clientError is an endpoint rejecting the URL (revoked/wrong/archived)."
            yellow "    → docker logs $AM_CONTAINER | grep -i notify | tail -5   (URL is redacted)"
            if [ "$_cred_present" -lt 0 ]; then
                yellow "    (D5 could not run, so I cannot tell inert-by-design from broken.)"
            fi
            D_FAIL=1
        elif [ "$_req" -eq 0 ]; then
            yellow "  ⚠ NO notification has been attempted since this Alertmanager started."
            yellow "    0 failures out of 0 attempts is not evidence of anything, and this"
            yellow "    line deliberately is not a green tick. The credential is UNPROVEN"
            yellow "    until something is actually sent."
            yellow "    → prove it now with ONE real alert:"
            yellow "        TALOS_ALERT_SEND_TEST=1 make observability-verify"
        else
            green "  ✓ $_reqok notification request(s) DELIVERED ($_sent notification(s)"
            green "    attempted, $_failed given up on)"
            if [ "$_reqfail" -gt 0 ]; then
                yellow "    ($_reqfail HTTP request(s) failed and were RETRIED successfully."
                yellow "     alertmanager_notifications_failed_total only counts a notification"
                yellow "     that never got through, which is the right basis for"
                yellow "     TalosAlertDeliveryFailing — but it means transient trouble is"
                yellow "     invisible to that alert. Worth a look if it keeps climbing.)"
            fi
        fi

        # ── D6b. ACTIVE probe. Opt-in, because it DELIVERS. ───────────────
        if [ "${TALOS_ALERT_SEND_TEST:-0}" = "1" ]; then
            yellow "  … TALOS_ALERT_SEND_TEST=1 — injecting ONE real alert."
            yellow "    This SENDS to whatever your credential points at. Expect a real"
            yellow "    message now and a second one when it resolves in ~2 minutes"
            yellow "    (send_resolved: true). It is labelled TalosAlertDeliveryProbe."
            # THE COUNTER TO WATCH IS SUCCESSES, NOT ATTEMPTS. The first
            # version of this probe waited for
            # alertmanager_notification_requests_total to increase and called
            # that DELIVERED. Driven against an unresolvable host it printed
            # "✓ probe DELIVERED — the endpoint accepted it" while the live
            # counters read requests_total=6, requests_FAILED_total=6 — six
            # consecutive failures — and the log read `Notify attempt failed,
            # will retry later ... no such host`. notifications_failed_total
            # was still 0 because Alertmanager had not yet given up retrying,
            # so watching THAT would have been just as wrong.
            # successes = requests_total - requests_failed_total.
            _b_req="$(_amsum alertmanager_notification_requests_total)"
            _b_reqfail="$(_amsum alertmanager_notification_requests_failed_total)"
            _b_ok=$(( _b_req - _b_reqfail ))
            _b_fail="$(_amsum alertmanager_notifications_failed_total)"
            _t0="$(python3 -c 'import time; print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))')"
            _t1="$(python3 -c 'import time; print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()+120)))')"
            if curl -fsS --max-time 10 -X POST -H 'Content-Type: application/json' \
                 --data "[{\"labels\":{\"alertname\":\"TalosAlertDeliveryProbe\",\"severity\":\"warning\",\"probe\":\"verify-observability\"},\"annotations\":{\"summary\":\"deliberate delivery probe from scripts/verify-observability.sh\",\"description\":\"If this reached your alert channel, delivery works. It resolves itself in two minutes; nothing is wrong.\"},\"startsAt\":\"$_t0\",\"endsAt\":\"$_t1\"}]" \
                 "$AM_URL/api/v2/alerts" >/dev/null 2>&1; then
                _seen=0
                _ok=0
                _deadline=$(( $(date +%s) + ${TALOS_ALERT_SEND_TEST_TIMEOUT:-90} ))
                while [ "$(date +%s)" -lt "$_deadline" ]; do
                    sleep 5
                    AM_METRICS="$(curl -fsS --max-time 10 "$AM_URL/metrics" 2>/dev/null || true)"
                    [ -n "$AM_METRICS" ] || continue
                    _n_req="$(_amsum alertmanager_notification_requests_total)"
                    _n_ok=$(( _n_req - $(_amsum alertmanager_notification_requests_failed_total) ))
                    [ "$_n_req" -gt "$_b_req" ] && _seen=1
                    # Keep waiting after a failed attempt: Alertmanager retries,
                    # and a retry that lands inside the window IS a delivery.
                    if [ "$_n_ok" -gt "$_b_ok" ]; then _ok=1; break; fi
                done
                _a_fail="$(_amsum alertmanager_notifications_failed_total)"
                _a_reqfail="$(_amsum alertmanager_notification_requests_failed_total)"
                if [ "$_seen" -eq 0 ]; then
                    yellow "  ⚠ INCONCLUSIVE: no notification request left Alertmanager within"
                    yellow "    ${TALOS_ALERT_SEND_TEST_TIMEOUT:-90}s. group_wait is 30s, so that is"
                    yellow "    normally ample. The known way to hit this is a probe from an"
                    yellow "    earlier run still being ACTIVE: the group is then inside its 5m"
                    yellow "    group_interval and a second notification is deferred. Probes"
                    yellow "    self-resolve after 2 minutes, and a re-run AFTER that was measured"
                    yellow "    to deliver normally — so wait two minutes and try again, or raise"
                    yellow "    TALOS_ALERT_SEND_TEST_TIMEOUT."
                elif [ "$_ok" -eq 0 ]; then
                    red "  ✗ the probe was SENT and NOT DELIVERED. Every notification request"
                    red "    Alertmanager made in the window failed"
                    red "    ($((_a_reqfail - _b_reqfail)) failed request(s),"
                    red "    $((_a_fail - _b_fail)) notification(s) given up on). The credential"
                    red "    is present and well-formed but NOT accepted — unreachable host,"
                    red "    revoked URL, wrong workspace, or the wrong receiver type."
                    yellow "    → docker logs $AM_CONTAINER | grep -i notify | tail -5"
                    yellow "      (Alertmanager redacts the URL in that log line.)"
                    D_FAIL=1
                else
                    green "  ✓ probe DELIVERED — a notification request completed successfully."
                    green "    (This proves the ENDPOINT ACCEPTED THE POST, not that a human"
                    green "    saw it: a valid webhook for an archived or muted channel accepts"
                    green "    just as happily. Go and confirm the message appeared where you"
                    green "    expect it — that last link is not testable from here.)"
                fi
            else
                red "  ✗ could not POST the probe alert to $AM_URL/api/v2/alerts"
                D_FAIL=1
            fi
        fi
    fi

    if [ "$D_FAIL" -eq 0 ] && [ "$_cred_present" -eq 0 ]; then
        # The summary must not claim more than the legs proved. Its first
        # version read "...every credential the running config names is present,
        # well-formed and not failing" and printed that verbatim over a stack
        # with ZERO credentials -- a green whose words denied the two yellow
        # lines directly above it. Same class as everything else in this arc:
        # a field whose name implies a verdict the measurement does not carry.
        green "  ✓ transport up, loopback-bound, credential dir contained outside"
        green "    every checkout — but DELIVERY IS INERT: no credential is"
        green "    configured, so no alert reaches anyone. Not a failure; it is the"
        green "    shipping state. See the file names above to enable it."
    elif [ "$D_FAIL" -eq 0 ] && [ "${_req:-0}" -eq 0 ]; then
        # Credentials configured and well-formed, but nothing has been sent.
        # "not failing" would be literally true and read as "working" — the
        # same overstatement the inert branch above was written to avoid.
        green "  ✓ transport up, loopback-bound, credentials contained outside every"
        green "    checkout, and every credential the running config names is present"
        green "    and well-formed — but NOTHING HAS BEEN SENT YET, so delivery is"
        green "    still unproven. TALOS_ALERT_SEND_TEST=1 proves it."
    elif [ "$D_FAIL" -eq 0 ]; then
        green "  ✓ transport up, loopback-bound, credentials contained outside every"
        green "    checkout, every credential the running config names is present and"
        green "    well-formed, and ${_reqok:-?} notification request(s) have been"
        green "    delivered with none outstanding."
    else
        FAIL=1
    fi
fi

# ══════════════════════════════════════════════════════════════════════════
# LEG E — the running Alertmanager is using the alertmanager.yml in the
#         checkout that feeds it.
#
# WHY THIS EXISTS
# ---------------
# #666 named this as its own largest residual and left it: leg A byte-compares
# the PROMETHEUS container's mounted files, legs B/C compare PROMETHEUS's
# loaded config and rules — and NOTHING compared Alertmanager's. So the exact
# #625/#645/#666 failure, in the one component whose whole job is reaching a
# human: edit alertmanager.yml, forget the reload, delivery keeps using the old
# routing, and every existing leg reports green. That matters most immediately
# after a credential is added, because that is the edit an operator makes.
#
# WHAT #666 MEASURED, AND WHY IT IS NOT THE OBSTACLE IT LOOKED LIKE
# -----------------------------------------------------------------
# `/api/v2/status` returns 2357 bytes against a 13267-byte file, which reads
# like most of the file is unrepresented. It is not. Re-measured here:
#   * 213 of the file's 250 lines are COMMENT or BLANK (it documents four
#     receiver options that do not ship). 37 lines are configuration.
#   * The file declares 26 leaf fields. The API reports 58. Leaf paths the file
#     declares and the API does NOT report: ZERO.
#   * The 32 extra API leaves are Alertmanager's filled-in defaults.
#   * 4 shared paths differ in value, all ONE class: Alertmanager re-prints
#     each matcher canonically (`severity = "critical"` -> `severity="critical"`).
# The re-marshal drops nothing. The size gap is commentary.
#
# NOTE the field name: the JSON key is `config.original`, which reads as "the
# file as given". It is not — it is `Config.String()`, i.e. yaml.Marshal of the
# parsed struct, which is why the defaults are there and the comments are not.
#
# TWO STAGES, AND STAGE 2 IS THE AUTHORITY — the same shape leg C uses for
# exprs, for the same reason.
#
#   STAGE 1 (always; no container): recursive subset — everything this checkout
#   DECLARES is in effect. Catches every ADD and CHANGE drift, which is the
#   whole "edited and never reloaded" failure. It is ONE-DIRECTIONAL, and that
#   is a real blind spot: delete `max_alerts: 20` from disk without reloading
#   and the process keeps applying it while a subset check reports green. Leg B
#   has the identical hole and names it. Closed here only for the collections
#   Alertmanager never invents on its own — receiver NAMES, the child-route
#   tree, and inhibit_rules — where an entry in the process and not on disk is
#   unambiguous drift rather than a filled-in default.
#
#   STAGE 2 (default on): run THIS CHECKOUT's alertmanager.yml through the SAME
#   BINARY — the image ID of the running container, so it cannot drift with a
#   version bump — and diff the two marshals BIDIRECTIONALLY. Both sides are
#   filled in by the same code, so the defaults cancel exactly: measured
#   BYTE-IDENTICAL, 2357 B against 2357 B, on a healthy stack. That removes the
#   need for a defaults list, a SECRET_KEYS list and the matcher normalisation
#   all at once, and it closes the deletion hole. #666's leg C rejected an
#   allow-list of what to COMPARE because it fails SILENT; a one-directional
#   subset is that same failure in a different dimension, so it is the fallback
#   here and not the verdict.
#
# THE TWO FAIL-SAFE ARMS (leg C's, and they are why this cannot rot):
#   * a key the REPO SETS that this leg cannot compare is a hard FAIL. Here that
#     is exactly the redaction case: an inline credential marshals to `<secret>`
#     on BOTH sides, so two DIFFERENT inline credentials compare equal. It is
#     reported rather than skipped — and it is a finding in its own right,
#     because a credential literal in a tracked config file is the containment
#     violation leg D exists to prevent. The `*_file` house pattern has no such
#     gap: paths are not redacted.
#   * a key only the RUNNING process has is a hard FAIL when its value is
#     truthy and a named WARNING when it is empty/zero — so an Alertmanager
#     upgrade that adds a defaulted field cannot make this gate permanently red.
#     A permanently-red gate trains you to ignore it, which is this script's own
#     header warning.
#
# SECRETS. No credential is read, hashed, compared or printed by this leg.
#   * Alertmanager redacts every secret-TYPED field to the literal `<secret>`
#     (measured across smtp_auth_password, slack_api_url, api_url, webhook url,
#     basic_auth.password and routing_key with dummy values). The redaction set
#     is therefore DERIVED from the data — value == "<secret>" — never from a
#     key list that a version bump could outdate.
#   * The disk side of a redacted field is never read. The leg reports the PATH.
#   * The stage-2 reference container is fed the CONFIG directory only, never
#     the secrets mount. It can do this because Alertmanager opens `*_file`
#     credentials at NOTIFY time, not load time — the same fact leg D5 relies
#     on. It publishes no port (it is queried through `docker exec`), joins no
#     network, and gossips nowhere (`--cluster.listen-address=`).
#
# STATED LIMITS:
#   * Stage 2 spawns and removes one throwaway container per run (~4 s). If
#     docker refuses, or the reference never becomes ready, the leg reports
#     stage 1's verdict and SAYS the result is one-directional. Set
#     TALOS_AM_REF_CHECK=0 to skip it deliberately — that also prints the
#     degradation rather than hiding it.
#   * If the reference container EXITS, this checkout's alertmanager.yml does
#     not load at all. That is a hard FAIL and is reported as such: it is a
#     stronger finding than any drift.
#   * Stage 2's diff is REPORTED ONLY WHEN STAGE 1 IS CLEAN. When the process
#     has not reloaded, every drifted field would otherwise be printed twice —
#     once in the repo's own terms and once again amid default-level noise,
#     burying the actionable lines. Stage 1's findings are a strict subset of
#     stage 2's in that state, so nothing is lost: fix them, re-run, and stage
#     2 reports whatever remains. Named here rather than left implied.
#   * This compares the CONFIG. It cannot tell you the routing is correct, only
#     that the process is running the routing on disk. Whether a message
#     reaches a human is leg D6.
#   * The reference container has a FIXED name (AM_REF_NAME). Two concurrent
#     runs of this script fight over it: the second's cleanup removes the
#     first's reference mid-query, and the first then reports "stage 2 did not
#     run" — the loud, one-directional direction, never a false green.
#   * `templates:` is compared as a LIST OF PATHS, not as content. If this
#     config ever names notification-template files, an edited template would
#     be invisible to both stages — the path is unchanged. It is `[]` today,
#     which is why this is a note rather than a second comparison; add one
#     before the first template file lands.
#   * The remedy this leg prints, `make observability-reload`, reloads
#     Alertmanager as well as Prometheus — it was Prometheus-only until this
#     change, which would have made every leg-E failure quote a target that
#     could not clear it.
#   * Leg A byte-compares the PROMETHEUS container's mounts and is deliberately
#     NOT extended to Alertmanager's. Two reasons: (a) it would have to hash the
#     credential mount, and no byte of a credential is hashed anywhere in this
#     script; (b) the truncation defect leg A exists for is SUBSUMED here —
#     stage 2 marshals the HOST file and compares it to what the process serves,
#     so a container reading a truncated prefix diverges and is caught by
#     EFFECT. A truncation that parses identically is, by definition, not a
#     divergence.
#   * Like leg B, the file compared is the one the RUNNING CONTAINER reads,
#     resolved through its own mount table — not a path relative to this
#     script. In a worktree the stack is fed by the main clone, and the leg says
#     so rather than reporting a false divergence against a checkout that feeds
#     nothing.
# ══════════════════════════════════════════════════════════════════════════
bold "  E. Alertmanager's LOADED config matches alertmanager.yml on disk"

AM_REF_NAME="${AM_REF_NAME:-talos-am-refcheck}"
AM_REF_OUT="$(mktemp -t am-ref-XXXXXX)"
AM_REF_STATE="skipped"
AM_REF_WHY=""

_am_ref_cleanup() { docker rm -fv "$AM_REF_NAME" >/dev/null 2>&1 || true; }
trap _am_ref_cleanup EXIT

if ! docker inspect "$AM_CONTAINER" >/dev/null 2>&1 \
   || [ "$(docker inspect -f '{{.State.Running}}' "$AM_CONTAINER" 2>/dev/null)" != "true" ]; then
    yellow "  ⚠ '$AM_CONTAINER' is not running — leg E did NOT run. Nothing below has"
    yellow "    compared the loaded Alertmanager config. (Leg D reports the absence.)"
else
    # Resolve the config file the CONTAINER actually reads, through its OWN
    # mounts — the same discipline leg B uses, and for the same reason: a
    # worktree has its own copy that no container mounts, and comparing the
    # running process against a checkout that does not feed it is a category
    # error that manufactures a divergence.
    AM_MOUNTS="$(docker inspect "$AM_CONTAINER" \
        --format '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}|{{.Destination}}|{{.RW}}{{"\n"}}{{end}}{{end}}')"
    AM_CFG_ARG="$(docker inspect "$AM_CONTAINER" --format '{{json .Config.Cmd}}' \
        | python3 -c 'import json,sys
try: a=json.load(sys.stdin) or []
except Exception: a=[]
print(next((x.split("=",1)[1] for x in a if x.startswith("--config.file=")),
           "/etc/alertmanager/alertmanager.yml"))')"
    AM_CFG_HOST=""
    while IFS='|' read -r src dst _rw; do
        [ -n "${src:-}" ] || continue
        hostsrc="${src#/host_mnt}"
        [ -e "$hostsrc" ] || hostsrc="$src"
        case "$AM_CFG_ARG" in
            "$dst")   AM_CFG_HOST="$hostsrc" ;;
            "$dst"/*) AM_CFG_HOST="$hostsrc/${AM_CFG_ARG#"$dst"/}" ;;
        esac
    done <<< "$AM_MOUNTS"

    if [ -z "$AM_CFG_HOST" ] || [ ! -f "$AM_CFG_HOST" ]; then
        red "  ✗ the container's --config.file ($AM_CFG_ARG) resolves to no host file"
        yellow "    → Alertmanager is reading a config no checkout on this host provides,"
        yellow "      so nothing can verify what it is routing. Mount it, or set"
        yellow "      AM_CONTAINER to the one you meant."
        FAIL=1
    else
        _amdir="$( (cd "$(dirname "$AM_CFG_HOST")" && pwd -P) 2>/dev/null || true)"
        _root="$(cd "$ROOT" && pwd -P)"
        # `case`, not `grep` — ROOT contains '.claude' for a worktree and a
        # regex '.' would match any character.
        case "$_amdir" in "$_root"|"$_root"/*) _amdir_in_root=1 ;; *) _amdir_in_root=0 ;; esac
        if [ "$_amdir_in_root" -eq 0 ]; then
            yellow "  ⚠ the running Alertmanager is fed by $AM_CFG_HOST, not $ROOT"
            yellow "    (checking the stack against ITS OWN source; a worktree's copy is"
            yellow "     not mounted, so this says nothing about your branch)"
        fi

        # ── STAGE 2 reference marshal: the same binary, this checkout's file ──
        if [ "${TALOS_AM_REF_CHECK:-1}" != "1" ]; then
            AM_REF_WHY="TALOS_AM_REF_CHECK=0 — skipped deliberately"
        else
            AM_IMAGE="$(docker inspect -f '{{.Image}}' "$AM_CONTAINER" 2>/dev/null || true)"
            if [ -z "$AM_IMAGE" ]; then
                AM_REF_WHY="could not read the running container's image ID"
            else
                _am_ref_cleanup
                if docker run -d --name "$AM_REF_NAME" --network none \
                       -v "$(dirname "$AM_CFG_HOST")":/etc/alertmanager/conf:ro \
                       "$AM_IMAGE" \
                       "--config.file=/etc/alertmanager/conf/$(basename "$AM_CFG_HOST")" \
                       "--storage.path=/tmp/am-ref" \
                       "--cluster.listen-address=" >/dev/null 2>&1; then
                    _deadline=$(( $(date +%s) + ${TALOS_AM_REF_TIMEOUT:-30} ))
                    while [ "$(date +%s)" -lt "$_deadline" ]; do
                        if [ "$(docker inspect -f '{{.State.Running}}' "$AM_REF_NAME" 2>/dev/null)" != "true" ]; then
                            AM_REF_STATE="exited"
                            break
                        fi
                        if docker exec "$AM_REF_NAME" wget -q -O - \
                               'http://127.0.0.1:9093/api/v2/status' > "$AM_REF_OUT" 2>/dev/null \
                           && [ -s "$AM_REF_OUT" ]; then
                            AM_REF_STATE="ok"
                            break
                        fi
                        sleep 1
                    done
                    [ "$AM_REF_STATE" = "skipped" ] && \
                        AM_REF_WHY="the reference container never became ready in ${TALOS_AM_REF_TIMEOUT:-30}s"
                else
                    AM_REF_WHY="'docker run' of $AM_IMAGE was refused"
                fi
            fi
        fi

        if [ "$AM_REF_STATE" = "exited" ]; then
            red "  ✗ $AM_CFG_HOST DOES NOT LOAD. A fresh Alertmanager on the same image"
            red "    exited rather than serving it, so this checkout could not be applied"
            red "    even with a reload — whatever the running process is serving, it is"
            red "    not this file."
            docker logs "$AM_REF_NAME" 2>&1 | grep -i 'level=ERROR' | tail -2 | sed 's/^/      /' \
                || docker logs "$AM_REF_NAME" 2>&1 | tail -2 | sed 's/^/      /'
            AM_REF_WHY="$AM_CFG_HOST does not load — see the error above"
            FAIL=1
        fi
        _am_ref_cleanup

        AM_URL="$AM_URL" AM_CFG_HOST="$AM_CFG_HOST" \
        AM_REF_OUT="$([ "$AM_REF_STATE" = "ok" ] && printf '%s' "$AM_REF_OUT")" \
        AM_REF_WHY="$AM_REF_WHY" \
        python3 - <<'AMEOF'
import json, os, re, sys, urllib.request
import yaml

FAIL = 0
def red(m):    print("\033[31m%s\033[0m" % m)
def yellow(m): print("\033[33m%s\033[0m" % m)
def green(m):  print("\033[32m%s\033[0m" % m)

am  = os.environ["AM_URL"]
cfg = os.environ["AM_CFG_HOST"]
REDACTED = "<secret>"

def status_config(fetch):
    """Parse an /api/v2/status body into (yaml_text, parsed). `config.original`
    is Config.String(), i.e. the MARSHALLED config — not the file text."""
    try:
        d = json.loads(fetch)
        txt = d["config"]["original"]
        return txt, (yaml.safe_load(txt) or {})
    except Exception as e:
        return None, e

try:
    with urllib.request.urlopen(am + "/api/v2/status", timeout=10) as r:
        body = r.read().decode()
except Exception as e:
    red("  ✗ cannot read %s/api/v2/status: %s" % (am, e))
    yellow("    → leg E cannot compare anything. This is a GAP, not a pass.")
    sys.exit(1)

live_txt, live = status_config(body)
if live_txt is None:
    red("  ✗ %s/api/v2/status did not carry a parseable config: %s" % (am, live))
    sys.exit(1)

try:
    disk = yaml.safe_load(open(cfg).read()) or {}
except Exception as e:
    red("  ✗ %s does not parse as YAML: %s" % (cfg, e))
    sys.exit(1)

# ── shared helpers ────────────────────────────────────────────────────────
def leaves(o, p=""):
    out = {}
    if isinstance(o, dict):
        for k, v in o.items():
            out.update(leaves(v, p + "/" + str(k)))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            out.update(leaves(v, "%s[%d]" % (p, i)))
    else:
        out[p] = o
    return out

# Alertmanager parses each matcher into labels.Matcher and re-prints it
# canonically: `severity = "critical"` on disk, `severity="critical"` from the
# API. MEASURED as the only value-level difference on a healthy stack (4 of 4).
# Applied to BOTH sides, so it need only be deterministic.
_MATCH = re.compile(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(=~|!~|!=|=)\s*(.*?)\s*$')
def norm_matcher(v):
    if not isinstance(v, str):
        return v
    m = _MATCH.match(v)
    if not m:
        return v
    name, op, val = m.groups()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
        val = val[1:-1]
    return '%s%s"%s"' % (name, op, val)

def norm(path, v):
    return norm_matcher(v) if re.search(r"matchers\[\d+\]$", path) else v

# ── STAGE 1: everything this checkout DECLARES is in effect ───────────────
dl = {p: norm(p, v) for p, v in leaves(disk).items()}
ll = {p: norm(p, v) for p, v in leaves(live).items()}

redacted_repo = sorted(p for p in dl if p in ll and ll[p] == REDACTED)
missing, changed = [], []
for p in sorted(dl):
    if p in redacted_repo:
        continue
    if p not in ll:
        missing.append(p)
    elif dl[p] != ll[p]:
        changed.append(p)

# ARM 1 — a key the REPO SETS that this leg cannot compare is a hard FAIL.
if redacted_repo:
    red("  ✗ %d setting(s) this checkout declares are CREDENTIAL LITERALS, which"
        % len(redacted_repo))
    red("    Alertmanager redacts to <secret> on both sides — so this leg cannot")
    red("    tell whether the running value is the one in the file:")
    for p in redacted_repo:
        yellow("      %s   (path only; no value read from either side)" % p)
    yellow("    → a credential in a TRACKED config file is also the containment")
    yellow("      violation leg D exists to prevent. Move it to the *_file form")
    yellow("      (api_url_file / url_file), which is a PATH and compares exactly.")
    FAIL = 1

if missing or changed:
    red("  ✗ %d setting(s) in %s are NOT in effect:" % (len(missing) + len(changed), cfg))
    for p in missing:
        yellow("      %s: repo=%r running=<absent>" % (p, dl[p]))
    for p in changed:
        yellow("      %s: repo=%r running=%r" % (p, dl[p], ll[p]))
    yellow("    → the process has not re-read %s." % cfg)
    yellow("      Apply with 'make observability-reload'.")
    FAIL = 1

# Closure on the collections Alertmanager NEVER invents. Stage 1 is otherwise
# one-directional; these three are wholly repo-authored, so an entry the process
# has and the file does not is drift, never a filled-in default.
extra = []
for label, dv, lv in (
        ("receiver", [r.get("name") for r in (disk.get("receivers") or [])],
                     [r.get("name") for r in (live.get("receivers") or [])]),):
    for n in sorted(set(lv) - set(dv)):
        extra.append((label, n))
d_routes = len(((disk.get("route") or {}).get("routes")) or [])
l_routes = len(((live.get("route") or {}).get("routes")) or [])
if l_routes > d_routes:
    extra.append(("child route", "%d loaded vs %d on disk" % (l_routes, d_routes)))
d_inh, l_inh = len(disk.get("inhibit_rules") or []), len(live.get("inhibit_rules") or [])
if l_inh > d_inh:
    extra.append(("inhibit rule", "%d loaded vs %d on disk" % (l_inh, d_inh)))
if extra:
    red("  ✗ the running config has %d entr(y/ies) this checkout does not declare:"
        % len(extra))
    for label, n in extra:
        yellow("      %s %s" % (label, n))
    yellow("    → Alertmanager never invents a receiver, a child route or an inhibit")
    yellow("      rule, so this is a DELETED setting the process is still applying.")
    FAIL = 1

# ── STAGE 2: the reference marshal — the authority ────────────────────────
ref_path = os.environ.get("AM_REF_OUT") or ""
ref = None
if ref_path and os.path.isfile(ref_path):
    ref_txt, ref = status_config(open(ref_path).read())
    if ref_txt is None:
        ref = None

if ref is None:
    yellow("    ⚠ STAGE 2 DID NOT RUN (%s)." % (os.environ.get("AM_REF_WHY")
           or "no reference marshal was produced"))
    yellow("      The verdict above is ONE-DIRECTIONAL: it proves everything this")
    yellow("      checkout declares is in effect, and CANNOT see a setting DELETED")
    yellow("      from disk that the process is still applying (outside the three")
    yellow("      collections closed above). Not a pass for that case — a gap.")
elif not (missing or changed or redacted_repo or extra):
    rl = leaves(ref)
    both = set(rl) | set(ll)
    hard, soft = [], []
    for p in sorted(both):
        rv, lv = rl.get(p, "\0absent"), ll.get(p, "\0absent")
        if rv == lv:
            continue
        if rv == REDACTED and lv == REDACTED:
            continue          # already reported by ARM 1
        # ARM 2 — a key only the RUNNING process has: hard FAIL when truthy,
        # named WARNING when empty/zero. Both marshals come from the SAME
        # binary, so an extra key cannot be a filled-in default.
        if rv == "\0absent" and not lv:
            soft.append(p)
        else:
            hard.append((p, rv, lv))
    if hard:
        red("  ✗ STAGE 2: the running config differs from what %s marshals to," % cfg)
        red("    through the SAME Alertmanager binary — %d difference(s):" % len(hard))
        for p, rv, lv in hard[:12]:
            yellow("      %s: repo=%r running=%r"
                   % (p, "<absent>" if rv == "\0absent" else rv,
                      "<absent>" if lv == "\0absent" else lv))
        if len(hard) > 12:
            yellow("      ... and %d more" % (len(hard) - 12))
        yellow("    → defaults cancel exactly on both sides, so every line above is a")
        yellow("      REAL divergence — including a setting deleted from disk that the")
        yellow("      process still applies, which stage 1 cannot see.")
        yellow("      Apply with 'make observability-reload'.")
        FAIL = 1
    if soft:
        yellow("    ⚠ %d field(s) present only in the running config and EMPTY/zero on"
               % len(soft))
        yellow("      every object, so none can be hiding a divergence today:")
        for p in soft[:8]:
            yellow("        %s" % p)
        if len(soft) > 8:
            yellow("        ... and %d more" % (len(soft) - 8))
        yellow("      A non-empty one FAILS this leg rather than being skipped.")
    if not hard:
        green("  ✓ %s" % cfg)
        green("    is loaded EXACTLY: all %d declared leaf field(s) are in effect, and"
              % len(dl))
        green("    the running config is identical to what the same binary marshals")
        green("    from this file (%d leaf field(s) compared BIDIRECTIONALLY, defaults"
              % len(both))
        green("    included) — nothing extra, nothing deleted-but-still-applied.")

if (missing or changed or redacted_repo or extra):
    pass
elif ref is None:
    green("  ✓ all %d setting(s) declared by" % len(dl))
    green("    %s" % cfg)
    green("    are in effect (ONE-DIRECTIONAL — see the gap named just above)")

sys.exit(1 if FAIL else 0)
AMEOF
        [ $? -ne 0 ] && FAIL=1
    fi
fi
rm -f "$AM_REF_OUT" 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════════════
# LEG F — off-host backup egress (Tier 2): producer → collector → Prometheus
#
# WHY THIS EXISTS. `scripts/offhost-backup/upload.sh` is the only thing
# standing between losing this disk and losing 1,544 ml_examples + 384
# ml_disagreements — a month of human labelling that no re-clone recovers.
# Its two alerts (TalosOffhostBackupUploadFailing / TalosOffhostBackupStale)
# are BOTH gated on series the uploader itself publishes into node_exporter's
# textfile directory. So the alerts cannot see any failure that happens
# UPSTREAM of the textfile: an uploader writing to a directory node_exporter
# does not read produces no series, and `increase(absent[50h])` matches
# nothing. The producer and the collector agreeing with EACH OTHER is not the
# property that matters; the property that matters is that PROMETHEUS has the
# series, and that is what this leg checks.
#
# WHY IT IS NOT AN ALERT. The alerts deliberately cannot fire before the
# uploader's first run (an absent() arm would go permanently red on every
# deployment that does not use Tier 2, and permanent red trains operators to
# ignore red — see the comment above TalosOffhostBackupStale). That leaves
# "never wired up at all" with no live detector. This leg is that detector,
# and it runs where a human is watching.
#
# IT MUST BE HONEST WHEN THE ANSWER IS "NOT ENABLED". A leg that printed a
# green tick because nothing is configured would be a worse defect than the
# one it is checking for. Three states, and only one of them is a tick:
#   BROKEN     — configured (or scheduled) but the chain cannot deliver. FAILS.
#   NOT PROVEN — nothing is wired up. Does NOT fail, is NOT green, and says
#                out loud that neither alert can fire.
#   wired      — Prometheus is actually serving the series the loaded alerts
#                reference, and every kind has a recent success.
#
# EVERYTHING IS DERIVED, NOTHING IS HARDCODED. node_exporter's textfile
# directory comes from the LIVE container's argv plus its LIVE bind mounts;
# the series to look for and the staleness threshold come from the alert rules
# Prometheus has actually LOADED (/api/v1/rules), not from a file on disk and
# not from a list in this script. A hardcoded list is the next stale snapshot
# (check 65's own lesson).
#
# STATED LIMITS — every one of these can produce a `wired` tick over a chain
# that would fail in practice, and each was reasoned about rather than
# discovered later:
#   * It cannot tell an OFF-HOST destination from a local one. `enabled == 1`
#     means three env vars were set; a bucket served from this same disk would
#     tick green. Only the operator choosing the destination closes that, and
#     the key must live in a different trust domain from the ciphertext.
#   * It never opens an archive. That an object in the bucket DECRYPTS to a
#     restorable dump is `make drill ARGS="--source b2"`, and nothing else.
#   * The metric it reads is written by the uploader, so an uploader that
#     stamped a success it did not perform would pass. (`last_success` is only
#     stamped after a PUT returns success, which bounds this.)
#   * It checks the LaunchAgent's textfile directory but cannot check that
#     `cargo` and `aws` resolve on the plist's fixed PATH, or that the
#     passphrase helper is non-interactive under launchd. Those surface as a
#     failing scheduled run, i.e. as reason="config" in the counter.
#   * macOS/launchd only for the schedule half; on Linux the plist is absent
#     and that half reports as "not scheduled" rather than inspecting systemd.
#   * PLACEMENT: `make up` runs this whole script with `>/dev/null 2>&1` and
#     reacts only to its exit status, so a NOT-PROVEN verdict (which
#     deliberately exits 0) is INVISIBLE there. An operator sees leg F only via
#     `make observability-verify`. Making NOT PROVEN exit non-zero would fix
#     the visibility and break something worse — `make up` would then run
#     `observability-reload` and eventually declare the stack stale, on a host
#     whose Prometheus config is perfectly current. The narrow line `make up`
#     prints ("Prometheus is evaluating this checkout") is true and is not a
#     claim about backups; the line this script itself prints at the end WAS
#     the one that read green over an unproven chain, and that is the one
#     F_NOTPROVEN corrects.
# ══════════════════════════════════════════════════════════════════════════
bold "  F. off-host backup egress: producer → collector → Prometheus"

NE_CONTAINER="${NE_CONTAINER:-talos-node-exporter}"
# Tri-state, because two-state is what would have made this leg a liar. The
# script's closing line is an unqualified green tick, and "nothing is wired up"
# must not be allowed to reach it — an operator who reads a green summary over
# an unproven off-host chain has been told the opposite of the truth. 0 = wired
# or irrelevant, 1 = NOT PROVEN (does not fail the run, but the summary says so).
F_NOTPROVEN=0

if ! grep -qE '^[[:space:]]{2}node-exporter:[[:space:]]*$' "$STACK_ROOT/docker-compose.yml" 2>/dev/null; then
    yellow "  ⚠ $STACK_ROOT/docker-compose.yml declares no node-exporter service — this"
    yellow "    stack collects no textfile metrics at all, so neither the off-host"
    yellow "    alerts nor the restore-drill alert can ever have data. NOT PROVEN."
    F_NOTPROVEN=1
elif ! docker inspect "$NE_CONTAINER" >/dev/null 2>&1; then
    red "  ✗ compose declares a node-exporter service but container '$NE_CONTAINER'"
    red "    does not exist — every textfile metric is unscraped."
    yellow "    → docker compose up -d node-exporter"
    FAIL=1
elif [ "$(docker inspect -f '{{.State.Running}}' "$NE_CONTAINER")" != "true" ]; then
    red "  ✗ '$NE_CONTAINER' exists but is not running — every textfile metric is unscraped."
    FAIL=1
else
    NE_ARGV="$(docker inspect "$NE_CONTAINER" --format '{{json .Config.Cmd}}{{json .Args}}')"
    NE_MOUNTS="$(docker inspect "$NE_CONTAINER" \
        --format '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}|{{.Destination}}{{"\n"}}{{end}}{{end}}')"

    NE_ARGV="$NE_ARGV" NE_MOUNTS="$NE_MOUNTS" NE_CONTAINER="$NE_CONTAINER" \
    PROM_URL="$PROM_URL" STACK_ROOT="$STACK_ROOT" \
    python3 - <<'FEOF'
import json, os, plistlib, re, time, urllib.parse, urllib.request

FAIL = 0
NOTPROVEN = 0
def red(m):    print("\033[31m%s\033[0m" % m)
def yellow(m): print("\033[33m%s\033[0m" % m)
def green(m):  print("\033[32m%s\033[0m" % m)

prom = os.environ["PROM_URL"]
home = os.path.expanduser("~")
TEXTFILE_NAME = "talos_offhost_backup.prom"   # talos-offhost-backup/src/metrics.rs
PLIST = os.path.join(home, "Library", "LaunchAgents", "com.talos.offhost-backup.plist")

def promq(expr):
    """Return the list of samples, or None if Prometheus could not answer."""
    try:
        url = prom + "/api/v1/query?query=" + urllib.parse.quote(expr)
        with urllib.request.urlopen(url, timeout=10) as r:
            d = json.load(r)
        if d.get("status") != "success":
            return None
        return d["data"]["result"]
    except Exception:
        return None

# ── F1. Where does node_exporter actually read textfiles from, on the HOST?
#        argv gives the CONTAINER path; the bind mounts translate it back.
argv = []
for blob in re.findall(r'\[[^\]]*\]', os.environ.get("NE_ARGV", "")):
    try:
        argv += [a for a in json.loads(blob) if isinstance(a, str)]
    except Exception:
        pass

cdir = None
for i, a in enumerate(argv):
    if a.startswith("--collector.textfile.directory="):
        cdir = a.split("=", 1)[1]
    elif a == "--collector.textfile.directory" and i + 1 < len(argv):
        cdir = argv[i + 1]
if cdir is None:
    # node_exporter's own default when the flag is omitted.
    cdir = ""

if not any(a == "--collector.textfile" or a.startswith("--collector.textfile.")
           for a in argv):
    red("  ✗ '%s' does not enable --collector.textfile — the uploader's metric is"
        % os.environ["NE_CONTAINER"])
    red("    written to disk and read by nobody. Neither off-host alert can fire.")
    FAIL = 1
    cdir = None

ne_dir = None
if cdir:
    for line in os.environ.get("NE_MOUNTS", "").splitlines():
        if "|" not in line:
            continue
        src, dst = line.split("|", 1)
        # Docker Desktop reports macOS bind sources under /host_mnt.
        hostsrc = src[len("/host_mnt"):] if src.startswith("/host_mnt") else src
        if not os.path.exists(hostsrc):
            hostsrc = src
        if cdir == dst:
            ne_dir = hostsrc
        elif cdir.startswith(dst.rstrip("/") + "/"):
            ne_dir = os.path.join(hostsrc, cdir[len(dst.rstrip("/")) + 1:])
    if ne_dir is None:
        red("  ✗ '%s' reads textfiles from '%s', which NO bind mount maps to this host."
            % (os.environ["NE_CONTAINER"], cdir))
        red("    Nothing any host-side producer writes can ever be scraped.")
        FAIL = 1

# ── F2. Where would the uploader WRITE? Same precedence as the binary
#        (talos-offhost-backup/src/main.rs: TALOS_OFFHOST_TEXTFILE_DIR →
#        TALOS_TEXTFILE_DIR → $HOME/.talos/metrics/textfile_collector).
#        Resolved twice: for THIS shell, and for the scheduled job's plist.
def resolve_textfile_dir(env):
    for k in ("TALOS_OFFHOST_TEXTFILE_DIR", "TALOS_TEXTFILE_DIR"):
        v = (env.get(k) or "").strip()
        if v:
            return v, k
    return os.path.join(home, ".talos", "metrics", "textfile_collector"), "default"

def same(a, b):
    try:
        return os.path.realpath(a) == os.path.realpath(b)
    except Exception:
        return a == b

env_dir, env_src = resolve_textfile_dir(os.environ)

plist_env, plist_dir, plist_src = None, None, None
if os.path.isfile(PLIST):
    try:
        with open(PLIST, "rb") as f:
            plist_env = plistlib.load(f).get("EnvironmentVariables", {}) or {}
        plist_dir, plist_src = resolve_textfile_dir(plist_env)
    except Exception as e:
        yellow("  ⚠ %s exists but could not be parsed (%s) — the scheduled job's"
               % (PLIST, type(e).__name__))
        yellow("    textfile directory could not be checked.")

if ne_dir:
    if not same(env_dir, ne_dir):
        red("  ✗ TEXTFILE PATH MISMATCH. An uploader run from this environment writes to")
        red("      %s   (from %s)" % (env_dir, env_src))
        red("    but %s reads" % os.environ["NE_CONTAINER"])
        red("      %s" % ne_dir)
        red("    Prometheus would never see the series, so TalosOffhostBackupUploadFailing")
        red("    and TalosOffhostBackupStale could BOTH never fire — while")
        red("    'make offhost-status' reads the same override and reports green.")
        yellow("    → set TALOS_TEXTFILE_DIR (which docker-compose.yml also interpolates)")
        yellow("      rather than TALOS_OFFHOST_TEXTFILE_DIR, which no collector-side")
        yellow("      config reads.")
        FAIL = 1
    if plist_dir is not None and not same(plist_dir, ne_dir):
        red("  ✗ The SCHEDULED job writes its metric somewhere unscraped.")
        red("      plist: %s  (from %s)" % (plist_dir, plist_src))
        red("      %s reads: %s" % (os.environ["NE_CONTAINER"], ne_dir))
        FAIL = 1
    if plist_dir is not None and not same(plist_dir, env_dir):
        yellow("  ⚠ this shell and the scheduled job resolve DIFFERENT textfile")
        yellow("    directories (%s vs %s) — 'make offhost-status' and the daily run"
               % (env_dir, plist_dir))
        yellow("    are looking at different files.")

# ── F3. Which series do the LOADED alerts actually reference, and at what
#        staleness threshold? Read from Prometheus, not from a file on disk:
#        the rules that matter are the ones it has loaded.
alert_series, stale_secs, n_alerts = set(), None, 0
try:
    with urllib.request.urlopen(prom + "/api/v1/rules", timeout=10) as r:
        for grp in json.load(r)["data"]["groups"]:
            for rule in grp.get("rules", []):
                expr = rule.get("query", "") or ""
                if "talos_offhost_backup" not in expr:
                    continue
                n_alerts += 1
                alert_series.update(re.findall(r"talos_offhost_backup_[a-z_]+", expr))
                m = re.search(r"(\d+)\s*\*\s*3600", expr)
                if m:
                    v = int(m.group(1)) * 3600
                    stale_secs = v if stale_secs is None else min(stale_secs, v)
except Exception:
    yellow("  ⚠ could not read /api/v1/rules — the series list and the staleness")
    yellow("    threshold fall back to the shipped defaults.")

if n_alerts == 0:
    yellow("  ⚠ the running Prometheus has loaded NO alert rule referencing")
    yellow("    talos_offhost_backup_* — this stack has no off-host detector at all.")
if not alert_series:
    alert_series = {"talos_offhost_backup_enabled",
                    "talos_offhost_backup_failures_total",
                    "talos_offhost_backup_last_success_timestamp_seconds"}
if stale_secs is None:
    stale_secs = 168 * 3600

# ── F4. Is there a metric, and does Prometheus have it?
metric_path = os.path.join(ne_dir, TEXTFILE_NAME) if ne_dir else None
have_metric = bool(metric_path and os.path.isfile(metric_path))
scheduled = os.path.isfile(PLIST)

def parse_metric(path):
    enabled, last = 0, {}
    with open(path, "r", errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                continue
            if line.startswith("talos_offhost_backup_enabled "):
                enabled = int(float(line.split()[-1]))
            elif line.startswith("talos_offhost_backup_last_success_timestamp_seconds{"):
                m = re.search(r'kind="([^"]+)"\}\s+(\S+)', line)
                if m:
                    last[m.group(1)] = float(m.group(2))
    return enabled, last

if FAIL:
    pass                      # a path defect is already reported; do not also
                              # editorialise about freshness on top of it.
elif not have_metric:
    if scheduled:
        red("  ✗ the off-host upload IS scheduled (%s) but has never written a" % PLIST)
        red("    metric into %s — the daily job is failing before it reaches" % ne_dir)
        red("    its own reporting, so no alert can see it. Check ~/.talos/logs/offhost-backup.log.")
        FAIL = 1
    else:
        NOTPROVEN = 1
        yellow("  ⚠ NOT PROVEN — the off-host backup chain is NOT WIRED UP on this host.")
        yellow("    No %s in %s, and no LaunchAgent." % (TEXTFILE_NAME, ne_dir))
        yellow("    Consequences, stated rather than implied:")
        yellow("      * Every backup exists ONLY on the disk it insures. Disk loss,")
        yellow("        theft or fire is total loss of the ml_examples labelling.")
        yellow("      * NEITHER off-host alert can fire: no .prom file means no series,")
        yellow("        and increase(absent[50h]) / (… and enabled == 1) both match")
        yellow("        nothing. This is by design, and it is why THIS leg exists.")
        yellow("      * The drill is not a substitute. Its metric carries NO source")
        yellow("        label, so a green talos_backup_drill_last_success cannot")
        yellow("        distinguish a --source b2 run from a local-copy restore.")
        yellow("    → docs/offhost-backup.md § Operator setup, then 'make offhost-schedule'.")
else:
    enabled, last = parse_metric(metric_path)
    if enabled != 1:
        NOTPROVEN = 1
        yellow("  ⚠ NOT PROVEN — the uploader has run, but no destination is configured")
        yellow("    (talos_offhost_backup_enabled = 0 in %s)." % metric_path)
        yellow("    All three of TALOS_OFFHOST_B2_{BUCKET,ENDPOINT,REGION} must be set;")
        yellow("    every run is failing with reason=\"config\". Nothing is off-host.")
    else:
        # The consumer is the authority. A metric file the collector reads but
        # Prometheus does not serve is the failure this leg exists to name.
        missing = []
        for s in sorted(alert_series):
            res = promq(s)
            if res is None:
                yellow("  ⚠ could not query Prometheus for %s" % s)
            elif not res:
                missing.append(s)
        if missing:
            red("  ✗ %s exists and says enabled=1, but Prometheus serves NO samples for:"
                % metric_path)
            for s in missing:
                red("      %s" % s)
            red("    The alerts reference these series, so they cannot fire. The file is")
            red("    written where node_exporter reads it, so the break is downstream:")
            yellow("    → check the 'node-exporter' scrape job in observability/prometheus/")
            yellow("      prometheus.yml and node_textfile_scrape_error on that target.")
            FAIL = 1
        else:
            now = time.time()
            stale = [(k, v) for k, v in sorted(last.items())
                     if v <= 0 or (now - v) > stale_secs]
            if stale:
                red("  ✗ a destination is configured but the off-host copy is not current:")
                for k, v in stale:
                    if v <= 0:
                        red("      kind=%s: NEVER succeeded" % k)
                    else:
                        red("      kind=%s: last success %.1f h ago (limit %.0f h)"
                            % (k, (now - v) / 3600.0, stale_secs / 3600.0))
                red("    Everything since then exists only on the disk it insures.")
                FAIL = 1
            else:
                oldest = min(last.values()) if last else now
                green("  ✓ off-host egress wired: %d kind(s), newest success %.1f h ago,"
                      % (len(last), (now - oldest) / 3600.0))
                green("    metric at %s, and Prometheus is serving all %d series the loaded"
                      % (metric_path, len(alert_series)))
                green("    alert rules reference.")
                if not scheduled:
                    yellow("  ⚠ …but it is NOT SCHEDULED (%s absent), so it will go stale."
                           % PLIST)
                    yellow("    TalosOffhostBackupStale will catch that in %.0f h."
                           % (stale_secs / 3600.0))
                yellow("    NOT proven by this leg: that the destination is genuinely")
                yellow("    off-host, or that any object there decrypts to a restorable")
                yellow("    dump. That is 'make drill ARGS=\"--source b2\"'.")

# ── F5. The restore drill, because leg F keeps CITING it.
#
# Everything above points at `make drill ARGS="--source b2"` as the thing
# that proves an archive is readable. Citing a guard without saying whether
# it is passing is how the docs ended up naming a backstop that was not
# armed, so leg F states the drill's last outcome instead of assuming it.
#
# ADVISORY, NOT A FAILURE, and deliberately so on both counts:
#   * it does not set FAIL — a failing drill must not make `make up` decide
#     Prometheus is stale and start reloading it (see the placement limit in
#     this leg's header). The DETECTOR for this is the alert rule
#     TalosBackupRestoreDrillLastRunFailed; this line is a courtesy for the
#     operator already looking at a terminal, not a substitute for it.
#   * it reads PROMETHEUS, not the .prom file, for the same reason the rest
#     of this leg does: the consumer is the authority, and a file the
#     collector never served is not a signal.
last_status = promq("talos_backup_drill_last_status")
if last_status:
    v = float(last_status[0]["value"][1])
    succ = promq("talos_backup_drill_last_success_timestamp_seconds")
    age = None
    if succ:
        t = float(succ[0]["value"][1])
        age = (time.time() - t) / 86400.0 if t > 0 else None
    when = ("last SUCCESS %.1f days ago" % age) if age is not None else "NO success ever recorded"
    if v == 0:
        yellow("  ⚠ the LAST restore drill RAN AND FAILED (%s)." % when)
        yellow("    The drill is what certifies these backups are readable at all, and it")
        yellow("    is the guard the off-host docs name for 'the uploader was never")
        yellow("    scheduled'. Re-run it: make drill   (the alert on this is")
        yellow("    TalosBackupRestoreDrillLastRunFailed; this line does not replace it)")
    else:
        green("  ✓ the last restore drill passed (%s)." % when)
elif last_status is None:
    # NOT the same as "no series", and conflating them would be this file's
    # own misleading-report class: one says the guard is unarmed, the other
    # says the check could not run.
    yellow("  ⚠ could not query Prometheus for talos_backup_drill_last_status — the")
    yellow("    restore drill's state is UNKNOWN, not known-good.")
else:
    yellow("  ⚠ Prometheus serves no talos_backup_drill_last_status — the restore drill")
    yellow("    has never reported here, so the guard leg F cites above is UNARMED.")

raise SystemExit(1 if FAIL else (2 if NOTPROVEN else 0))
FEOF
    case $? in
        0) ;;
        2) F_NOTPROVEN=1 ;;
        *) FAIL=1 ;;
    esac
fi

echo
if [ "$FAIL" -ne 0 ]; then
    red "✗ the running observability stack and this repo DISAGREE."
    yellow "  Recover with: make observability-reload"
    yellow "  (if that does not clear it, the container predates the directory-mount"
    yellow "   fix — 'docker compose up -d --force-recreate prometheus' recreates it"
    yellow "   without touching the prometheus_data volume.)"
    exit 1
fi
green "✓ the running Prometheus AND Alertmanager are reading exactly what their"
green "  source checkout contains."
if [ "$F_NOTPROVEN" -ne 0 ]; then
    # Deliberately AFTER the green line and deliberately not an exit 1. The
    # green above is true and narrow — it is about config liveness. Letting it
    # stand alone as the last word over an off-host chain that has never run
    # would be this script telling an operator the opposite of the truth.
    yellow "…but see leg F: the off-host backup chain is NOT PROVEN. Every backup"
    yellow "  still exists only on the disk it insures, and neither off-host alert"
    yellow "  can fire until the uploader has run once."
fi
