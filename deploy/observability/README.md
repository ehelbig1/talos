# Talos observability — crypto invariants

Before this directory existed, a Vault misconfiguration silently broke
every `__memory_write__` in production for weeks. No alert fired because
no alert existed. This directory is the fix.

## What it monitors

Three classes of signals, all of them "the at-rest encryption is
working correctly":

1. **Orphan gauges** (`talos_{actor_memory,module_execution,workflow_execution}_orphaned_rows`) — number of rows whose `*_enc_key_id` FK points at a deleted DEK. Updated every 60s by a background task in `controller/src/main.rs`. **Should be 0 always.** Non-zero = data loss has already occurred.

2. **Crypto-path failure counters:**
   - `talos_kek_decrypt_failures_total{provider="active|legacy|both"}` — Vault or env KEK couldn't unwrap a DEK.
   - `talos_memory_write_failures_total{reason="crypto|db|other"}` — `__memory_write__` hook couldn't persist.
   - `talos_module_payload_encryption_failures_total{op,stage}` — module_executions `*_enc` column write/read failures.

3. **Vault backend state** — federated from Vault's own `/v1/sys/metrics` endpoint:
   - `vault_core_unsealed` — 0 = sealed (broken), 1 = unsealed (healthy).
   - `vault_core_handle_request` histogram — request latency (slow Vault = slow controller reads).

## Files in this directory

| File | Role |
|---|---|
| `alerts.yaml` | Prometheus alert rules. Drop-in-replaceable for PrometheusRule CRD. |
| `alertmanager-route.yaml` | Route config for Alertmanager. PagerDuty on `category: data-loss` or `crypto-broken`, Slack on warnings, Jira ticket on ops-hygiene. |
| `grafana-crypto-dashboard.json` | Grafana dashboard (import via UI or provision via `grafana.ini` `provisioning/dashboards`). |

## Wiring (minimum viable)

### 1. Prometheus scrape target

The controller exposes Prometheus text format at `/metrics/prometheus`
(separate from the existing per-user `/metrics` endpoint). Gated by a
shared-secret `PROMETHEUS_SCRAPE_TOKEN` bearer.

```yaml
# prometheus.yaml scrape_configs
- job_name: talos-controller
  metrics_path: /metrics/prometheus
  bearer_token_file: /etc/prometheus/secrets/talos-scrape-token
  static_configs:
    - targets: [talos-controller.talos.svc.cluster.local:8000]
  scheme: http  # in-cluster only — never expose publicly
```

Generate the token once: `openssl rand -hex 32`. Put it in a Kubernetes
Secret consumed by both controller (`PROMETHEUS_SCRAPE_TOKEN` env) and
Prometheus (mounted via `bearer_token_file`).

### 2. Vault scrape target

Vault exposes unauthenticated `/v1/sys/metrics` only when configured.
For a simpler start, use the `vault-agent` sidecar + telemetry stanza
in `vault.hcl`:

```hcl
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
}
```

Then add:

```yaml
- job_name: talos-vault
  metrics_path: /v1/sys/metrics
  params:
    format: [prometheus]
  bearer_token_file: /etc/prometheus/secrets/vault-scrape-token  # non-root token w/ metrics capability
  static_configs:
    - targets: [talos-vault.talos.svc.cluster.local:8200]
```

### 3. Alerts

```bash
# kube-prometheus-stack / Prometheus Operator
kubectl -n monitoring apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: talos-crypto
  labels: {app: talos}
spec:
$(cat alerts.yaml | sed 's/^/  /')
EOF
```

Or for vanilla Prometheus:

```bash
kubectl -n monitoring create configmap talos-alerts \
    --from-file=alerts.yaml -o yaml --dry-run=client | kubectl apply -f -
# then reference in Prometheus --rules.file=/etc/prometheus/rules/alerts.yaml
```

### 4. Alertmanager routing

`alertmanager-route.yaml` is a *fragment* — merge it into your existing
`alertmanager.yaml` under `route:` and `receivers:`. If you don't have
one yet:

```bash
kubectl -n monitoring create secret generic alertmanager-talos \
    --from-file=alertmanager.yaml=alertmanager-route.yaml \
    --from-literal=slack-webhook-oncall='<webhook url>' \
    --from-literal=pagerduty-routing-key='<pd integration key>'
```

The paths `/etc/alertmanager/secrets/*` in the config reference
projected volume mounts — wire them up in your Alertmanager
Deployment/StatefulSet.

### 5. Grafana dashboard

```bash
# via Grafana API
curl -X POST https://grafana.example.com/api/dashboards/db \
    -H "Authorization: Bearer $GRAFANA_API_KEY" \
    -H "Content-Type: application/json" \
    -d @grafana-crypto-dashboard.json

# or via kubectl when using the grafana-operator / Grafana Helm chart
kubectl -n monitoring create configmap talos-crypto-dashboard \
    --from-file=grafana-crypto-dashboard.json
# label it with grafana_dashboard=1 so the sidecar picks it up:
kubectl -n monitoring label configmap talos-crypto-dashboard grafana_dashboard=1
```

## Alert severity model

| `severity` | `category` | Behavior | Example |
|---|---|---|---|
| critical | data-loss | **PagerDuty + Slack oncall**, no grouping delay | orphaned DEK reference |
| critical | crypto-broken | **PagerDuty + Slack oncall** | both KEK providers failing |
| critical | availability | **PagerDuty** | controller down |
| warning | crypto-degraded | Slack oncall only | active KEK failing, legacy carrying |
| warning | persistence-degraded | Slack oncall only | DB pool saturated |
| warning | performance | Slack team channel | Vault p99 > 500ms |
| warning | leak | Slack team channel | DEK cache > 10k entries |
| warning | ops-hygiene | Jira ticket, weekly re-ping | no backup drill in 14 days |

Alerts can't be silenced without explicitly acknowledging them — there
are no `for: 30d` suppressions hiding in here. If an alert is noisy in
prod, fix the underlying metric or tune the threshold via PR, don't
silence.

## Testing the alerts

Confirm the full pipeline works end-to-end before you need it in
anger. There's a deliberate test path for each:

```bash
# 1. Orphan gauge — manually create an orphan row (dev only).
# Creates and then cleans up; fires TalosActorMemoryDEKOrphaned once.
kubectl -n talos exec deploy/talos-controller -- \
    psql $DATABASE_URL -c "
    BEGIN;
    SET session_replication_role = replica;  -- disable FK
    INSERT INTO actor_memory (actor_id, key, value_enc, value_key_id)
    SELECT (SELECT id FROM actors LIMIT 1),
           'test-orphan-' || gen_random_uuid(),
           '\\x00'::bytea,
           gen_random_uuid();  -- fake DEK id
    -- let it sit for >5m so alert fires (for: 5m)
    -- then:
    DELETE FROM actor_memory WHERE key LIKE 'test-orphan-%';
    COMMIT;"

# 2. KEK failures — wrong Vault token forces decrypt fail.
# In a dev cluster only:
kubectl -n talos set env deploy/talos-controller VAULT_TOKEN=invalid
# wait 2m for the counter to bump, verify alert fires, then:
kubectl -n talos rollout undo deploy/talos-controller

# 3. Vault sealed — simulate by sealing Vault manually:
kubectl -n talos exec statefulset/talos-vault-0 -- vault operator seal
# VaultSealed alert fires in 2m, then:
kubectl -n talos exec statefulset/talos-vault-0 -- \
    vault operator unseal "$(jq -r '.unseal_keys_b64[0]' /vault/file/bootstrap.json)"
```

Run this drill **once per quarter** — along with the backup/restore
drill at `scripts/drills/backup-restore.sh`. See `Makefile` target
`make drill-alerts` (scheduled for addition with the backup drill
work).

## See also

- **Operational runbook:** `../../docs/security/operational-runbook.md` — response procedures referenced in alert annotations
- **KEK migration plan:** `../../docs/security/kek-to-kms-plan.md` — recovery procedures when KEK provider is broken
- **Memory Phase B plan:** `../../docs/security/agent-memory-encryption-plan.md` — context for the encryption invariants these alerts protect
