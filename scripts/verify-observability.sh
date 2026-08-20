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
