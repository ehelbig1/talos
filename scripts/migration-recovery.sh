#!/usr/bin/env bash
# Capture migration logs from the next install attempt.
#
# Why: when `helm upgrade` fails with `pre-upgrade hooks failed: ... job
# talos-migrations failed: BackoffLimitExceeded`, the failed pod is often
# deleted by the K8s job-controller before kubectl can read its logs. By
# the time you run `kubectl logs job/talos-migrations` you get
# `error: timed out waiting for the condition` and no useful information.
#
# This script delete-and-tails: it removes the failed Job, kicks off a
# fresh install in the background, waits for the next pod to appear, and
# tails its logs in real time. Logs make it to your terminal before the
# job-controller GC's the pod.
#
# Usage:
#   scripts/migration-recovery.sh [NAMESPACE]
#
# NAMESPACE   — defaults to "talos"
#
# Required: kubectl in PATH and configured to talk to the target cluster.
#           install.sh present at /opt/talos/deploy/k3s/install.sh — adjust
#           INSTALL_SH below if your layout differs.
#
# Exit codes:
#   0  — install.sh exited 0 AND migration logs captured
#   1  — kubectl/install.sh missing
#   2  — install.sh failed (logs were captured; re-read them)

set -uo pipefail

NAMESPACE="${1:-talos}"
INSTALL_SH="${INSTALL_SH:-/opt/talos/deploy/k3s/install.sh}"
LOG_FILE="${LOG_FILE:-/tmp/talos-migration-recovery.log}"

# ── Pre-flight ───────────────────────────────────────────────────────────────
if ! command -v kubectl >/dev/null 2>&1; then
    echo "✗ kubectl not in PATH" >&2
    exit 1
fi
if [ ! -x "$INSTALL_SH" ]; then
    echo "✗ install.sh not found or not executable: $INSTALL_SH" >&2
    echo "  Override with: INSTALL_SH=/path/to/install.sh $0 $NAMESPACE" >&2
    exit 1
fi

echo "▶ Deleting any prior talos-migrations job in namespace '$NAMESPACE'"
kubectl -n "$NAMESPACE" delete job talos-migrations --ignore-not-found

echo "▶ Starting install.sh in background (output → $LOG_FILE)"
"$INSTALL_SH" > "$LOG_FILE" 2>&1 &
INSTALL_PID=$!

# ── Wait for the next migrations pod ─────────────────────────────────────────
echo "▶ Waiting for next migrations pod to appear (timeout 120s)..."
deadline=$(($(date +%s) + 120))
while ! kubectl -n "$NAMESPACE" get pods -l job-name=talos-migrations --no-headers 2>/dev/null | grep -q .; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "✗ no migrations pod appeared within 120s" >&2
        echo "  install.sh may have failed before the helm hook fired — check $LOG_FILE"
        wait $INSTALL_PID
        exit 2
    fi
    if ! kill -0 $INSTALL_PID 2>/dev/null; then
        echo "✗ install.sh exited before any pod appeared — check $LOG_FILE" >&2
        wait $INSTALL_PID
        exit 2
    fi
    sleep 1
done

echo "▶ Tailing migration logs..."
echo "─────────────────────────────────────────────"
# `kubectl logs -f` will exit when the pod terminates (success or failure),
# at which point we collect events and the install exit code.
kubectl -n "$NAMESPACE" logs -f -l job-name=talos-migrations --tail=200 || true
echo "─────────────────────────────────────────────"

echo "▶ Recent events (last 15):"
kubectl -n "$NAMESPACE" get events --sort-by=.lastTimestamp | tail -15

wait $INSTALL_PID
exit_code=$?
if [ $exit_code -eq 0 ]; then
    echo "✓ install.sh completed successfully"
else
    echo "✗ install.sh exited with code $exit_code — full output: $LOG_FILE"
    exit 2
fi
