#!/usr/bin/env bash
# One-off debug helper for the talos-migrations job. Spawns a Pod with
# the same image / command / DATABASE_URL the migrations Job uses, but
# with `restartPolicy: Never` so the failed Pod sticks around long
# enough to grab its logs. Use when a deploy fails at
# `pre-upgrade hooks failed: job talos-migrations failed:
# BackoffLimitExceeded` and the Job's pod was deleted before
# `kubectl logs` could grab the actual sqlx error.
#
# Usage: sudo bash /opt/talos/scripts/debug-migrate.sh
set -euo pipefail

NS="${TALOS_NAMESPACE:-talos}"
SECRET="${TALOS_BOOTSTRAP_SECRET:-talos-bootstrap}"
POD="sqlx-debug"

# Pull the controller image digest from the most recent install.env.
# Fall back to whatever the talos-migrations Job (still in cluster as
# a failed hook) is pointing at — kubectl reads the digest off the
# stale Job spec.
DIGEST=""
if [[ -n "${TALOS_CONTROLLER_DIGEST:-}" ]]; then
    DIGEST="$TALOS_CONTROLLER_DIGEST"
elif [[ -f /etc/talos/install.env ]]; then
    # The anchored `^TALOS_` pattern is intentionally loose on leading
    # whitespace — install.env files in the wild get hand-edited and
    # often end up indented. Strip leading whitespace before matching.
    DIGEST="$(grep -E '^[[:space:]]*TALOS_CONTROLLER_DIGEST=' /etc/talos/install.env | head -1 | sed -E 's/^[[:space:]]*//' | cut -d= -f2- | tr -d '"' || true)"
fi
if [[ -z "$DIGEST" ]]; then
    # Last-ditch: parse the talos-migrations Job's container image.
    DIGEST="$(kubectl -n "$NS" get job talos-migrations \
        -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null \
        | grep -oE 'sha256:[a-f0-9]+' || true)"
fi
if [[ -z "$DIGEST" ]]; then
    echo "ERROR: could not resolve controller image digest." >&2
    echo "  set TALOS_CONTROLLER_DIGEST=sha256:... and rerun." >&2
    exit 1
fi

IMAGE="ghcr.io/${TALOS_GHCR_OWNER:-ehelbig1}/talos-controller@${DIGEST}"

# Get rid of any prior debug pod (might be left over from a previous
# successful run that the user didn't clean up).
kubectl -n "$NS" delete pod "$POD" --ignore-not-found >/dev/null 2>&1 || true

# Apply the pod. Heredoc-from-a-file (the script itself is read by bash
# from a real file, not pasted), so YAML indentation is preserved
# byte-for-byte from the source — none of the terminal-paste-bracketing
# issues that bit us trying to do this interactively.
cat <<EOF | kubectl -n "$NS" apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${POD}
  namespace: ${NS}
  labels:
    # Stamp the same component label the chart applies to its
    # migrations Job pods so the NetworkPolicy on talos-postgres
    # admits us. Without this, k3s's bundled kube-router REJECTs
    # the connection (→ "Connection refused" from the postgres
    # side, even though the pod is happily listening). Found while
    # debugging the in-cluster Postgres rollout 2026-05-19.
    app.kubernetes.io/name: talos
    app.kubernetes.io/instance: talos
    app.kubernetes.io/component: migrations
spec:
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: debug
    image: ${IMAGE}
    command: ["/usr/local/cargo/bin/sqlx", "migrate", "run", "--source", "/app/migrations"]
    env:
    - name: DATABASE_URL
      valueFrom:
        secretKeyRef:
          name: ${SECRET}
          key: DATABASE_URL
    - name: RUST_LOG
      value: "sqlx=debug,info"
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      runAsUser: 10001
      seccompProfile:
        type: RuntimeDefault
EOF

echo
echo "▶ Waiting for the debug pod to finish (it should fail in <30s)…"
# Wait for terminal state. Don't `wait --for=condition=Ready` — the pod
# never becomes Ready (it's a one-shot command), it just exits.
for i in $(seq 1 60); do
    phase=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
    if [[ "$phase" == "Succeeded" || "$phase" == "Failed" ]]; then
        echo "▶ Pod phase: $phase"
        break
    fi
    sleep 1
done

echo
echo "═══════════════════════════════════════════════════════════════════"
echo "  sqlx migrate output"
echo "═══════════════════════════════════════════════════════════════════"
kubectl -n "$NS" logs "$POD" 2>&1 || true

echo
echo "═══════════════════════════════════════════════════════════════════"
echo "  Pod terminal state (exit code, reason, message)"
echo "═══════════════════════════════════════════════════════════════════"
kubectl -n "$NS" get pod "$POD" -o jsonpath='{range .status.containerStatuses[*]}{.name}: lastState={.lastState}{"\n"}state={.state}{"\n"}{end}' 2>&1 || true
echo

# Clean up so subsequent runs don't trip over an existing pod.
kubectl -n "$NS" delete pod "$POD" --ignore-not-found
