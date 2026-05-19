#!/usr/bin/env bash
# Standalone debug pod that emulates the vault-init Job's
# secret-patcher container, but with restartPolicy=Never so the pod
# stays around after failure (the Job's BackoffLimitExceeded
# semantics auto-delete the failing pod and we lose the logs).
#
# Adds `set -x` so every shell command is echoed, surfacing the
# exact line that exits non-zero.
#
# Usage: sudo bash /opt/talos/scripts/debug-secret-patcher.sh
set -euo pipefail

NS="${TALOS_NAMESPACE:-talos}"
SECRET="${TALOS_BOOTSTRAP_SECRET:-talos-bootstrap}"
CONTROLLER_DEPLOY="${TALOS_CONTROLLER_DEPLOY:-talos-controller}"
SA="talos-vault-init"
POD="secret-patcher-debug"

# Generate a fake "talos-controller-token" since we don't have the
# real one from vault-bootstrap. The script's logic doesn't actually
# care about token content — it just patches whatever string it
# reads. Use a clearly-marked debug value so we can spot it in the
# patched secret + roll it back later.
DEBUG_TOKEN="DEBUG-$(date +%s)-VAULT-TOKEN-FROM-DEBUG-SCRIPT"

kubectl -n "$NS" delete pod "$POD" --ignore-not-found >/dev/null 2>&1 || true

cat <<EOF | kubectl -n "$NS" apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${POD}
  namespace: ${NS}
spec:
  restartPolicy: Never
  serviceAccountName: ${SA}
  securityContext:
    runAsNonRoot: true
    runAsUser: 1001
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: debug
    image: alpine/k8s:1.31.4
    imagePullPolicy: IfNotPresent
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1001
      capabilities:
        drop: ["ALL"]
    env:
      - name: BOOTSTRAP_SECRET
        value: "${SECRET}"
      - name: CONTROLLER_DEPLOY
        value: "${CONTROLLER_DEPLOY}"
      - name: NAMESPACE
        value: "${NS}"
      - name: DEBUG_TOKEN
        value: "${DEBUG_TOKEN}"
    command:
      - /bin/sh
      - -c
      - |
        set -eux
        echo "secret-patcher-debug: starting"
        echo "secret-patcher-debug: NAMESPACE=\$NAMESPACE BOOTSTRAP_SECRET=\$BOOTSTRAP_SECRET CONTROLLER_DEPLOY=\$CONTROLLER_DEPLOY"

        # Skip the token-file check — supply via env var instead.
        NEW_TOKEN="\$DEBUG_TOKEN"

        CURRENT_B64=\$(kubectl -n "\$NAMESPACE" get secret "\$BOOTSTRAP_SECRET" \\
          -o jsonpath='{.data.VAULT_TOKEN}' 2>/dev/null || true)
        echo "secret-patcher-debug: CURRENT_B64 length=\$(printf '%s' "\$CURRENT_B64" | wc -c)"

        if [ -n "\$CURRENT_B64" ]; then
          CURRENT=\$(printf '%s' "\$CURRENT_B64" | base64 -d 2>/dev/null || true)
        else
          CURRENT=""
        fi
        echo "secret-patcher-debug: CURRENT='\$CURRENT'"

        case "\$CURRENT" in
          __pending_vault_init__|dev-root|"")
            echo "secret-patcher-debug: would patch (DEBUG MODE — patching with marked debug value)"
            NEW_B64=\$(printf '%s' "\$NEW_TOKEN" | base64 | tr -d '\n')
            PAYLOAD=\$(printf '{"data":{"VAULT_TOKEN":"%s"}}' "\$NEW_B64")
            echo "secret-patcher-debug: invoking kubectl patch secret"
            kubectl -n "\$NAMESPACE" patch secret "\$BOOTSTRAP_SECRET" \\
              --type=merge -p "\$PAYLOAD"
            echo "secret-patcher-debug: patch returned exit \$?"
            ;;
          *)
            echo "secret-patcher-debug: would leave alone (already non-placeholder)"
            ;;
        esac
        echo "secret-patcher-debug: done"
        sleep 30
        echo "secret-patcher-debug: exiting"
EOF

echo "▶ Waiting for pod to finish (max 60s)…"
for i in $(seq 1 60); do
    PHASE=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
    case "$PHASE" in
        Succeeded|Failed) echo "▶ pod phase: $PHASE"; break;;
    esac
    sleep 1
done

echo
echo "═══════════════════════════════════════════════════"
echo "  pod logs"
echo "═══════════════════════════════════════════════════"
kubectl -n "$NS" logs "$POD" 2>&1 || true

echo
echo "═══════════════════════════════════════════════════"
echo "  pod terminal state"
echo "═══════════════════════════════════════════════════"
kubectl -n "$NS" get pod "$POD" -o jsonpath='{range .status.containerStatuses[*]}{.name}: {.state}{"\n"}{end}' 2>&1

echo
echo "═══════════════════════════════════════════════════"
echo "  VAULT_TOKEN in bootstrap secret (first 60 chars)"
echo "═══════════════════════════════════════════════════"
kubectl -n "$NS" get secret "$SECRET" -o jsonpath='{.data.VAULT_TOKEN}' | base64 -d | head -c 60 ; echo

kubectl -n "$NS" delete pod "$POD" --ignore-not-found >/dev/null
