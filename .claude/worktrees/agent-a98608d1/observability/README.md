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
├── prometheus.yml                      # Prometheus configuration
├── alerts.yml                          # Alert rules
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

### prometheus.yml

Prometheus scraping configuration:
- Scrapes Talos worker every 10 seconds at `/metrics`
- Self-monitoring for Prometheus, Grafana, Jaeger
- Support for Docker Compose and Kubernetes service discovery
- Global labels for cluster/environment

**Key sections**:
```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'talos-worker'
    scrape_interval: 10s
    static_configs:
      - targets: ['talos-worker:9090']
```

### alerts.yml

Production-ready alert rules (12 total):

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

**Service Health Alerts** (3):
- TalosWorkerDown
- PrometheusScrapeFailure
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

Edit `prometheus.yml`:

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
# Check if worker is running and exposing metrics
curl http://localhost:9090/metrics

# Check Prometheus logs
docker logs talos-prometheus | tail -50

# Verify network
docker network inspect observability_observability
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

**Last Updated**: 2026-02-17
**Maintained By**: Talos Team
