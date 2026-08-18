#!/usr/bin/env bash
#
# Verify that the RUNNING dev Prometheus is actually reading the files in this
# repo — i.e. that a merged, deployed config change is in effect.
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

bold "▶ observability liveness: is the running Prometheus reading THIS repo?"

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

diffs = subset(disk, loaded)
if diffs:
    red("  \u2717 settings in %s are NOT in effect:" % cfg_host)
    for p, w, g in diffs[:12]:
        yellow("      %s: repo=%r running=%r" % (p, w, g))
    if len(diffs) > 12:
        yellow("      ... and %d more" % (len(diffs) - 12))
    yellow("    \u2192 the process has not re-read %s. Apply with 'make observability-reload'." % cfg_host)
    FAIL = 1
else:
    green("  \u2713 every setting in %s is in effect (%d scrape job(s))"
          % (cfg_host, len(loaded.get("scrape_configs") or [])))

# ── C. every alert on disk is loaded, AND ITS DEFINITION MATCHES ──────────
#
# WHY THIS COMPARES DEFINITIONS AND NOT JUST NAMES.
# The first cut of this leg compared alert NAME SETS. That is blind to the
# case that actually shipped: #644 did not only ADD three alerts, it also
# REWROTE the expr of the existing `TalosWorkerFleetBuildSkew` from
# `talos_worker_fleet_build_skew_workers > 0` (a series that had been
# deleted, so the alert could never fire) to `..._build_skew_builds > 0`.
# The name was in both sets, so a name-set gate reported ✓ while the running
# process kept evaluating the un-fireable expr. A gate that cannot see the
# repair of a broken detector is this repo's own defect class applied to its
# own tooling — so the comparison is over the whole rule: expr, `for`,
# labels and annotations.
#
# EXPR COMPARISON IS TWO-STAGE, and the second stage is the authority.
# `/api/v1/rules` returns Prometheus's own re-rendered PromQL, not the repo
# text. Measured differences on this stack, all pure formatting: newlines
# collapsed, `on()` → `on ()`, `1.0` → `1`, `[50h]` → `[2d2h]`, and label
# matchers re-sorted alphabetically. A textual compare is therefore a
# permanently-red gate, which is the failure mode this script's header warns
# about. Stage 1 is a cheap textual normalisation that agrees on 52 of 54
# live rules; stage 2 hands every remaining disagreement to
# `promtool promql format`, i.e. Prometheus's OWN parser and printer, which
# canonicalises all five classes above. Typical cost is 0–2 `docker exec`s.
#
# STATED LIMITS:
#   * If `promtool promql format --experimental` is unavailable (older
#     Prometheus, or the flag withdrawn), stage 2 cannot run. The leg then
#     reports the stage-1 verdict and SAYS it is unadjudicated, rather than
#     silently downgrading to a name-set comparison.
#   * Stage 1 can only produce false MISMATCHES, never false matches, for
#     formatting differences — and stage 2 resolves those. The one direction
#     it can miss is a difference confined to whitespace INSIDE a quoted
#     label value (`{job="a b"}` vs `{job="ab"}`); stage 2 catches that too
#     whenever it runs.
#   * A recording rule is not compared; only alerting rules.
entries = loaded.get("rule_files") or []
if not entries:
    red("  ✗ the running Prometheus has NO rule_files at all — no alert can fire")
    FAIL = 1

on_disk = {}
for entry in entries:
    hf = to_host(entry)
    if hf is None or not os.path.isfile(hf):
        red("  ✗ rule_files entry %r resolves to no file through the container's mounts" % entry)
        yellow("    → Prometheus GLOBS rule_files, so this loads ZERO groups silently.")
        FAIL = 1
        continue
    doc = yaml.safe_load(open(hf).read()) or {}
    for g in doc.get("groups") or []:
        for r in g.get("rules") or []:
            if r.get("alert"):
                on_disk[r["alert"]] = r

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
    """`for:` is `30m` on disk and 1800 (seconds) from the API."""
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

live_rules = {r["name"]: r for g in api("/rules")["groups"] for r in g["rules"]
              if r.get("type") == "alerting"}

missing = sorted(set(on_disk) - set(live_rules))
extra   = sorted(set(live_rules) - set(on_disk))

drifted = []
unadjudicated = 0
for name in sorted(set(on_disk) & set(live_rules)):
    d, l = on_disk[name], live_rules[name]
    facets = []
    if norm_expr(d.get("expr")) != norm_expr(l.get("query")):
        # stage 2: let Prometheus's own parser adjudicate before reporting.
        agreed = False
        if PROMTOOL_OK:
            cd, cl = canon(d.get("expr") or ""), canon(l.get("query") or "")
            if cd is not None and cl is not None:
                agreed = (cd == cl)
            else:
                unadjudicated += 1
        else:
            unadjudicated += 1
        if not agreed:
            facets.append(("expr", d.get("expr"), l.get("query")))
    if norm_for(d.get("for")) != norm_for(l.get("duration")):
        facets.append(("for", d.get("for"), l.get("duration")))
    if (d.get("labels") or {}) != (l.get("labels") or {}):
        facets.append(("labels", d.get("labels"), l.get("labels")))
    if (d.get("annotations") or {}) != (l.get("annotations") or {}):
        facets.append(("annotations", "<differs>", "<differs>"))
    if facets:
        drifted.append((name, facets))

if missing:
    red("  ✗ defined on disk but NOT loaded by the running Prometheus:")
    for a in missing:
        yellow("      " + a)
    yellow("    → this is the '#625 merged and never took effect' symptom exactly.")
    FAIL = 1
if extra:
    red("  ✗ loaded by Prometheus but NOT defined on disk:")
    for a in extra:
        yellow("      " + a)
    yellow("    → the process is running rules this checkout does not contain.")
    FAIL = 1
if drifted:
    red("  ✗ loaded under the right NAME but with a DIFFERENT definition:")
    for name, facets in drifted:
        yellow("      %s — %s differs" % (name, ", ".join(f[0] for f in facets)))
        for facet, want, got in facets:
            if facet == "annotations":
                continue
            yellow("        %s: repo=%r running=%r" % (facet, want, got))
    yellow("    → the process is evaluating a STALE definition of an alert that")
    yellow("      still exists by name — a name-only check cannot see this.")
    yellow("      Apply with 'make observability-reload'.")
    FAIL = 1
if not PROMTOOL_OK and any(f[0] == "expr" for _, fs in drifted for f in fs):
    yellow("    ⚠ 'promtool promql format --experimental' is unavailable in %s, so"
           % PROM_CONTAINER)
    yellow("      the expr differences above are UNADJUDICATED — they may be pure")
    yellow("      formatting. Compare by hand before treating them as drift.")

if on_disk and not missing and not extra and not drifted:
    green("  ✓ all %d alert(s) on disk are loaded with matching definitions%s"
          % (len(on_disk), "" if PROMTOOL_OK else " (expr compared textually only)"))
elif not on_disk:
    red("  ✗ found no alert definitions on disk — cannot verify anything")
    FAIL = 1

sys.exit(1 if FAIL else 0)
PYEOF
[ $? -ne 0 ] && FAIL=1

echo
if [ "$FAIL" -ne 0 ]; then
    red "✗ the running Prometheus and this repo DISAGREE."
    yellow "  Recover with: make observability-reload"
    yellow "  (if that does not clear it, the container predates the directory-mount"
    yellow "   fix — 'docker compose up -d --force-recreate prometheus' recreates it"
    yellow "   without touching the prometheus_data volume.)"
    exit 1
fi
green "✓ the running Prometheus is reading exactly what its source checkout contains."
