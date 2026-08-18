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
MOUNTS="$MOUNTS" PROM_URL="$PROM_URL" ROOT="$ROOT" \
PROM_CMD="$(docker inspect "$PROM_CONTAINER" --format '{{json .Config.Cmd}}')" \
python3 - <<'PYEOF'
import json, os, sys, urllib.request
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

# ── C. every alert defined on disk is loaded ──────────────────────────────
entries = loaded.get("rule_files") or []
if not entries:
    red("  \u2717 the running Prometheus has NO rule_files at all — no alert can fire")
    FAIL = 1

on_disk = set()
for entry in entries:
    hf = to_host(entry)
    if hf is None or not os.path.isfile(hf):
        red("  \u2717 rule_files entry %r resolves to no file through the container's mounts" % entry)
        yellow("    \u2192 Prometheus GLOBS rule_files, so this loads ZERO groups silently.")
        FAIL = 1
        continue
    doc = yaml.safe_load(open(hf).read()) or {}
    for g in doc.get("groups") or []:
        for r in g.get("rules") or []:
            if r.get("alert"):
                on_disk.add(r["alert"])

live = {r["name"] for g in api("/rules")["groups"] for r in g["rules"]
        if r.get("type") == "alerting"}

missing = sorted(on_disk - live)
extra   = sorted(live - on_disk)
if missing:
    red("  \u2717 defined on disk but NOT loaded by the running Prometheus:")
    for a in missing:
        yellow("      " + a)
    yellow("    \u2192 this is the '#625 merged and never took effect' symptom exactly.")
    FAIL = 1
if extra:
    red("  \u2717 loaded by Prometheus but NOT defined on disk:")
    for a in extra:
        yellow("      " + a)
    yellow("    \u2192 the process is running rules this checkout does not contain.")
    FAIL = 1
if on_disk and not missing and not extra:
    green("  \u2713 all %d alert(s) on disk are loaded" % len(on_disk))
elif not on_disk:
    red("  \u2717 found no alert definitions on disk \u2014 cannot verify anything")
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
#   D4. the UI is bound to loopback ONLY.
#
# D4 is the one that matters most and the one a lint cannot do. Alertmanager's
# /api/v2/silences lets any caller silence every detector in this system, and
# Alertmanager ships no authentication. A published port bypasses the host
# firewall, and docker-compose.override.yml is gitignored and scanned by no
# lint — so the LIVE binding is the only trustworthy answer.
#
# STATED LIMITS:
#   * Secrets are checked for EXISTENCE and PERMISSIONS only. Their contents
#     are never read, hashed, printed or logged (CLAUDE.md: presence only).
#     So this cannot tell you a credential is VALID — only
#     TalosAlertDeliveryFailing can, and only once a send is attempted.
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
bold "  D. alert delivery: transport, credential containment, and binding"

AM_CONTAINER="${AM_CONTAINER:-talos-alertmanager}"

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
    if ! curl -fsS --max-time 10 "${AM_URL:-http://127.0.0.1:9093}/-/ready" >/dev/null 2>&1; then
        red "  ✗ Alertmanager is running but ${AM_URL:-http://127.0.0.1:9093}/-/ready is unreachable"
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
                    if [ "$n" -eq 0 ]; then
                        yellow "  ⚠ no credential files in $real — delivery is INERT."
                        yellow "    Alertmanager reads api_url_file/url_file at NOTIFY time, so it"
                        yellow "    starts and loads cleanly and then fails every send. Nothing"
                        yellow "    reaches a human until one is dropped in. Not a failure: this is"
                        yellow "    the documented shipping state, and it is what"
                        yellow "    TalosAlertDeliveryFailing exists to make visible."
                    elif [ "$bad_mode" -eq 0 ]; then
                        green "  ✓ $n credential file(s) present, mode-checked (contents never read)"
                    fi
                fi
                ;;
        esac
    done <<< "$(docker inspect "$AM_CONTAINER" \
        --format '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}|{{.Destination}}|{{.RW}}{{"\n"}}{{end}}{{end}}')"

    if [ "$D_FAIL" -eq 0 ]; then
        green "  ✓ transport up, loopback-bound, credentials contained outside every checkout"
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
