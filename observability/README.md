# Talos Observability Configuration

This directory contains all configuration files for the Talos observability stack:
- Prometheus (metrics)
- Grafana (dashboards)
- Jaeger (distributed tracing)

---

## Directory Structure

```
observability/
├── README.md                           # This file
├── prometheus/
│   └── prometheus.yml                  # Prometheus configuration
├── alerts.yml                          # WASM/worker alert rules (dev stack)
└── grafana/
    ├── provisioning/
    │   ├── datasources/
    │   │   └── datasources.yml        # Auto-provision Prometheus & Jaeger
    │   └── dashboards/
    │       └── dashboards.yml         # Auto-load dashboard directory
    └── dashboards/
        └── talos-wasm-runtime.json    # Pre-built dashboard
```

---

## Files

### prometheus/prometheus.yml

Prometheus scraping configuration:
- Scrapes the Talos **controller** every 15 seconds at `/metrics/prometheus`
- Scrapes every Talos **worker** replica every 10 seconds at `/metrics`
- Self-monitoring for Prometheus, Grafana, Jaeger
- Global labels for cluster/environment

**Key sections**:
```yaml
scrape_configs:
  # Every talos_* series lives in the CONTROLLER process.
  # `/metrics/prometheus` is the scrape route; `/metrics` is a
  # different, authenticated dashboard route — not this one.
  - job_name: 'talos-controller'
    metrics_path: '/metrics/prometheus'
    static_configs:
      - targets: ['controller:8000']

  # `worker` is the compose SERVICE name. dns_sd (not static) because the
  # service runs with replicas — an A lookup returns every replica, while a
  # static target resolves to one arbitrary replica.
  - job_name: 'talos-worker'
    bearer_token: 'dev-token'      # matches METRICS_AUTH_TOKENS default
    dns_sd_configs:
      - names: ['worker']
        type: 'A'
        port: 9090                 # METRICS_PORT default
```

> **Before 2026-08-02 this file scraped nothing of Talos.** There was no
> controller job at all, and the worker job was wrong three ways at once
> (host `talos-worker` does not resolve, port 9091 vs the real 9090 default,
> bearer `dev-metrics-token` vs the real `dev-token`). Structural lint
> **check 65** now fails the build if a job an alert selects on via
> `up{job="…"}` is missing, if a `rule_files` entry no compose file mounts,
> or if an alert references a `talos_*` metric no Rust source registers.
> There is a fourth direction, 65(d): no alert name may be defined in more
> than one mounted rule file. Read check 65's header in
> `scripts/lint-structural.sh` for its six stated limits before relying on it. 65(b) is now enforced **per compose file**, so
> dropping this stack's rule mounts fails the lint; the remaining documented
> holes are a glob `rule_files` entry (rejected though Prometheus allows it),
> extra scrape jobs no alert selects on, mount mode (`:rw` passes), and
> `wasm_*` metrics (65(c) only inspects `talos_*`).

**Note on the two stacks.** Only `docker-compose.yml` can exercise these
alerts: its Prometheus shares `talos-network` with the controller and worker.
`docker-compose.observability.yml`, run standalone as its header documents,
has only the `observability` bridge and no Talos service (the worker entry is
commented out), so `controller:8000` and the `worker` A-record do not resolve
and no `talos_*` series is collected there. Both stacks also bind host `:9090`
and the container name `talos-prometheus`, so they cannot run at once.

### Alert rules

Two rule files are mounted into the container at `/etc/prometheus/rules/`:

| Mounted as | Source | Covers |
|---|---|---|
| `wasm-alerts.yml` | `observability/alerts.yml` | WASM runtime / worker (11 rules) |
| `talos-alerts.yaml` | `deploy/helm/talos/files/alerts.yaml` | Controller `talos_*` invariants (26 rules) |

`talos-alerts.yaml` is **bind-mounted, never copied** — it is the same file the
chart's `PrometheusRule` embeds via `.Files.Get`, so the dev rules and the
production CRD cannot drift. (`deploy/observability/alerts.yaml` is a symlink to
it for the same reason.)

**Five `talos_*` series named by these alerts are absent from a healthy
controller's `/metrics/prometheus`** (verified 2026-08-02 against the live
endpoint): `talos_auth_attempts_total`, `talos_auth_failures_total`,
`talos_kek_decrypt_failures_total`, `talos_memory_write_failures_total`,
`talos_module_payload_encryption_failures_total`. All five are registered in
`talos-metrics`, so structural check 65(c) passes — but they are labelled
`CounterVec`s with no pre-seeded label combination, and a prometheus `*Vec`
exports nothing until some label set is first touched. That is NOT the same as
"the alert can never fire" (an `increase(...) > 0` rule fires once the series
appears and has two samples), but it does mean "detector absent" and "detector
present and quiet" are indistinguishable on a healthy stack. Deliberately not
pre-seeded here: `talos_auth_failures_total{method,reason}` has an open reason
set, and #623's own rule is that seeding a label combination nothing writes
"would imply a wired signal that doesn't exist". Filed as follow-up, not fixed
in this change. (The five #623 detectors added in that PR — `talos_wasm_log_
orphaned_total` etc. — ARE seeded and do appear.)

`TalosWorkerDown` is defined **once**, in `talos-alerts.yaml`. Until 2026-08-02
`observability/alerts.yml` carried a second copy (`for: 1m`, `component=worker`
vs the canonical `for: 2m`, `category=availability`). That was invisible while
`docker-compose.yml` mounted no rules at all; mounting both files loaded both
copies and fired both on one worker outage — observed live. Alertmanager cannot
dedup them because the label sets differ, so it is two pages and two
contradictory runbook pointers for one incident. The dev copy was deleted and
structural lint **check 65(d)** now fails on any alert name defined in more than
one mounted rule file.

### alerts.yml

WASM/worker alert rules (11 total).

> **These are not currently exercisable, even though `up{job="talos-worker"}`
> is now 1.** Verified 2026-08-02 by scraping the live worker: its
> `/metrics` returns `target_info` and nothing else. The instruments behind
> these alerts are real (`talos-worker-runtime/src/metrics.rs` declares
> `wasm.executions.total`, `wasm.errors.total`, …), but the OTEL Prometheus
> exporter emits an instrument only after its first recorded measurement, so
> on an idle worker every `wasm_*` series is ABSENT rather than zero. A green
> target here means "reachable", not "producing the series the rules need" —
> and structural check 65 cannot see the difference, because 65(c) only
> inspects `talos_*` names.


**Performance Alerts** (5):
- HighWASMErrorRate (> 0.1 errors/sec)
- CriticalWASMErrorRate (> 1.0 errors/sec)
- SlowWASMExecution (P95 > 500ms)
- VerySlowWASMExecution (P95 > 2000ms)
- LowCacheHitRate (< 70%)

**Resource Alerts** (3):
- HighWASMMemoryUsage (> 1GB)
- TooManyActiveInstances (> 500)
- HighRetryRate (> 0.5 retries/sec)

**Service Health Alerts** (1):
- PrometheusScrapeFailure (any target down > 5m — broader than the per-job
  `TalosWorkerDown`/`TalosControllerDown`, which live in `talos-alerts.yaml`)

**Throughput Alerts** (2):
- LowWASMThroughput (< 10 executions/sec)
- NoWASMExecutions (30 min idle)

### grafana/provisioning/datasources/datasources.yml

Auto-provisions datasources on Grafana startup:
- **Prometheus** (metrics) - http://prometheus:9090
- **Jaeger** (traces) - http://jaeger:16686

No manual configuration needed!

### grafana/provisioning/dashboards/dashboards.yml

Auto-loads dashboards from `grafana/dashboards/` directory.
Any JSON file in that directory will be imported automatically.

### grafana/dashboards/talos-wasm-runtime.json

Pre-built production dashboard with 10 panels:

**Top Row** (5 stats):
1. Executions/sec - Current throughput
2. P95 Latency - 95th percentile execution time
3. Cache Hit Rate - % of cache hits
4. Error Rate - Errors per second
5. Active Instances - Current instance count

**Graphs** (5 time series):
6. Execution Rate - Success vs error trend
7. Execution Duration - P50/P95/P99 percentiles
8. Errors by Type - Pie chart of error distribution
9. Cache Performance - Hits vs misses stacked area
10. Memory Usage - Memory consumption over time

**Features**:
- Auto-refresh every 10 seconds
- Last 1 hour time range (adjustable)
- Dark theme
- Mean and max calculations in legends
- Threshold colors (green/yellow/red)

---

## Customization

### Add a New Alert

Edit `alerts.yml`:

```yaml
groups:
  - name: custom_alerts
    interval: 30s
    rules:
      - alert: CustomAlert
        expr: your_metric > threshold
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Alert summary"
          description: "Alert description"
```

Reload Prometheus:
```bash
docker exec talos-prometheus kill -HUP 1
```

### Modify Scrape Interval

Edit `prometheus/prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'talos-worker'
    scrape_interval: 5s  # Changed from 10s
```

Restart Prometheus:
```bash
docker-compose -f docker-compose.observability.yml restart prometheus
```

### Add a Custom Dashboard

1. Create dashboard in Grafana UI
2. Export as JSON: Share → Export → Save to file
3. Copy to `grafana/dashboards/my-dashboard.json`
4. Restart Grafana (or wait for auto-reload)

---

## Prometheus Queries

Useful queries for dashboards and alerts:

```promql
# Current execution rate (req/sec)
rate(wasm_executions_total[5m])

# Success rate (%)
100 * rate(wasm_executions_total{status="success"}[5m]) / rate(wasm_executions_total[5m])

# P50 latency
histogram_quantile(0.50, rate(wasm_execution_duration_ms_bucket[5m]))

# P95 latency
histogram_quantile(0.95, rate(wasm_execution_duration_ms_bucket[5m]))

# P99 latency
histogram_quantile(0.99, rate(wasm_execution_duration_ms_bucket[5m]))

# Cache hit rate (%)
100 * rate(wasm_cache_hits[5m]) / (rate(wasm_cache_hits[5m]) + rate(wasm_cache_misses[5m]))

# Error rate by type
sum by (type) (rate(wasm_errors_total[5m]))

# Active instances
wasm_instances_active

# Memory usage (MB)
wasm_memory_used_bytes / (1024 * 1024)

# Retry rate
rate(wasm_retries_total[5m])
```

---

## Backup & Restore

### Backup Dashboards

```bash
# Export all dashboards
docker exec talos-grafana grafana-cli admin export-dashboards \
  > backups/dashboards-$(date +%Y%m%d).json

# Backup Grafana data directory
docker run --rm -v grafana-data:/data \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/grafana-$(date +%Y%m%d).tar.gz /data
```

### Backup Prometheus Data

```bash
# Backup Prometheus data
docker run --rm -v prometheus-data:/data \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/prometheus-$(date +%Y%m%d).tar.gz /data
```

### Restore

```bash
# Restore Grafana
docker run --rm -v grafana-data:/data \
  -v $(pwd)/backups:/backup \
  alpine sh -c "cd /data && tar xzf /backup/grafana-YYYYMMDD.tar.gz --strip 1"

# Restart Grafana
docker-compose -f docker-compose.observability.yml restart grafana
```

---

## Version Information

| Component | Version | Notes |
|-----------|---------|-------|
| Prometheus | v2.48.0 | Metrics collection |
| Grafana | 10.2.2 | Visualization |
| Jaeger | 1.52 | Distributed tracing |

---

## Troubleshooting

### Prometheus Not Scraping

**Check targets**: http://localhost:9090/targets

If target is DOWN:
```bash
# Check the worker is running and exposing metrics. The worker's metrics port
# is NOT published to the host (host :9090 is Prometheus itself), so probe it
# from inside the network — and send the bearer token or you get a 401.
docker compose exec worker \
  wget -qO- --header 'Authorization: Bearer dev-token' http://localhost:9090/metrics | head

# Check Prometheus logs
docker logs talos-prometheus | tail -50

# Verify network (docker-compose.yml stack; the observability stack's net
# is <project>_observability instead)
docker network inspect talos_talos-network
```

### Grafana Dashboard Shows No Data

**Possible causes**:
1. Prometheus not scraping worker
2. Worker not generating metrics
3. Time range too narrow

**Fix**:
```bash
# Verify Prometheus has data
curl 'http://localhost:9090/api/v1/query?query=wasm_executions_total'

# Check Grafana datasource
# Grafana → Configuration → Data Sources → Prometheus → Test
```

### Alerts Not Firing

```bash
# Check alert status in Prometheus
http://localhost:9090/alerts

# View alert evaluation logs
docker logs talos-prometheus | grep -i alert
```

---

## Resources

- **Prometheus Documentation**: https://prometheus.io/docs
- **Grafana Documentation**: https://grafana.com/docs
- **Jaeger Documentation**: https://www.jaegertracing.io/docs
- **PromQL Guide**: https://prometheus.io/docs/prometheus/latest/querying/basics/

---

**Last Updated**: 2026-08-02
**Maintained By**: Talos Team
