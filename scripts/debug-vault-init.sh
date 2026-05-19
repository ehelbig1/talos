#!/usr/bin/env bash
# Run install.sh in the background and capture vault-init pod logs the
# moment its pod reaches a terminal state. The vault-init Job has a
# short-ish ttlSecondsAfterFinished and the pod can be cleaned up
# before an operator can grab its logs interactively — this script
# closes the race.
#
# Usage: sudo bash /opt/talos/scripts/debug-vault-init.sh
set -euo pipefail

NS="${TALOS_NAMESPACE:-talos}"

echo "[$(date +%T)] starting install.sh in background"
( /opt/talos/deploy/k3s/install.sh > /tmp/install.log 2>&1 ; echo "[install exit: $?]" ) &
INSTALL_PID=$!

LAST_STATUS=""
CAPTURED=0

while kill -0 "$INSTALL_PID" 2>/dev/null; do
    POD=$(kubectl -n "$NS" get pods -l job-name=talos-vault-init \
            -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    if [ -n "${POD:-}" ]; then
        STATUS=$(kubectl -n "$NS" get pod "$POD" \
                  -o jsonpath='{.status.phase}' 2>/dev/null || true)
        if [ "$STATUS" != "$LAST_STATUS" ]; then
            echo "[$(date +%T)] vault-init pod: $POD ($STATUS)"
            LAST_STATUS="$STATUS"
        fi
        # Capture once when terminal state reached.
        if [ "$CAPTURED" -eq 0 ] && { [ "$STATUS" = "Succeeded" ] || [ "$STATUS" = "Failed" ]; }; then
            echo "==================================================="
            echo "  vault-bootstrap logs (init container)"
            echo "==================================================="
            kubectl -n "$NS" logs "$POD" -c vault-bootstrap --tail=200 2>&1 || true
            echo
            echo "==================================================="
            echo "  secret-patcher logs (main container)"
            echo "==================================================="
            kubectl -n "$NS" logs "$POD" -c secret-patcher --tail=100 2>&1 || true
            echo
            echo "==================================================="
            echo "  pod describe (last 40 lines)"
            echo "==================================================="
            kubectl -n "$NS" describe pod "$POD" 2>&1 | tail -40 || true
            CAPTURED=1
        fi
    fi
    sleep 3
done

wait "$INSTALL_PID" 2>/dev/null || true

echo
echo "==================================================="
echo "  tail of install.log"
echo "==================================================="
tail -25 /tmp/install.log

echo
echo "==================================================="
echo "  final cluster state"
echo "==================================================="
kubectl -n "$NS" get jobs,pods -l job-name=talos-vault-init 2>&1 || true
echo
kubectl -n "$NS" get pods 2>&1 || true
