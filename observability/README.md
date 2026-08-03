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
├── rules/
│   └── alerts.yml                      # WASM/worker alert rules (dev stack)
├── alerts_test.yml                     # promtool fixture — deliberately NOT
│                                       #   in rules/ (Prometheus would fail
│                                       #   to parse it as a rule file)
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
> or if an alert references a `talos_*` **or `wasm_*`** metric no Rust source
> registers.
> There is a fourth direction, 65(d): no alert name may be defined in more
> than one mounted rule file. Read check 65's header in
> `scripts/lint-structural.sh` for its seven stated limits before relying on it. 65(b) is now enforced **per compose file**, so
> dropping this stack's rule mounts fails the lint; **65(c) covers `wasm_*` as
> of 2026-08-02** — it derives the exported name from the OTEL declaration
> rather than looking for a literal, and run against the pre-fix tree it fails
> on six real defects. Mount mode was a documented hole
> until 2026-08-03; 65(b) now requires `:ro` on every resolved rule-file mount,
> and `make observability-verify` fails any read-write bind on the Prometheus
> container. The remaining documented holes are a glob `rule_files` entry
> (rejected though Prometheus allows it), extra scrape jobs no alert selects
> on, and 65(a) scanning whole rule files rather than `expr:` blocks.

**Note on the two stacks.** Only `docker-compose.yml` can exercise these
alerts: its Prometheus shares `talos-network` with the controller and worker.
`docker-compose.observability.yml`, run standalone as its header documents,
has only the `observability` bridge and no Talos service (the worker entry is
commented out), so `controller:8000` and the `worker` A-record do not resolve
and no `talos_*` series is collected there. Both stacks also bind host `:9090`
and the container name `talos-prometheus`, so they cannot run at once.

### Alert rules

Two rule files are mounted into the container, each via a **directory** mount:

| Mounted as | Source directory | Covers |
|---|---|---|
| `/etc/prometheus/rules/alerts.yml` | `observability/rules/` | WASM runtime / worker (10 rules) |
| `/etc/prometheus/rules-chart/alerts.yaml` | `deploy/helm/talos/files/` | Controller `talos_*` invariants (26 rules) |

**Why directories and not the individual files.** A single-file bind mount can
leave the container serving *corrupted* content once the host file is replaced,
and git replaces rather than rewrites files in place.

*Measured* here 2026-08-03: the host rules file was 21953 bytes and the
container served a byte-exact 6464-byte prefix **of that same current file**,
cut mid-word. It parsed, loaded 13 groups / 37 rules, and `/api/v1/rules` looked
perfectly healthy while #625's `WASMMetricsPipelineDead` was simply absent.

*Mechanism*, reproduced deterministically on 2026-08-03 (Docker Desktop 29.6.2,
VirtioFS) after two earlier attempts failed: the trigger is the host file
acquiring a **new inode**, which every `git checkout` of a changed file does.
While a file is edited *in place* the mount tracks it correctly and
indefinitely; the first replacement freezes the container's cached **size** at
its last-known value permanently (observed frozen for 26 h), while the **data**
path keeps resolving by name and returning the current bytes. Net: current
content clamped to the superseded length — 6464 here is exactly the previous
committed version's byte length. "The mount pins the inode" is the one
explanation ruled out; the data came from the *new* file. A same-length or
in-place edit cannot exhibit the bug and will "prove" a single-file mount is
fine, which is how the first two attempts came back negative.

Directory mounts were correct in every equivalent test, including on a
four-day-old container — but one directory-mounted container was observed frozen
and could not be made to repeat it. So the mount change removes a
**deterministic, every-time** failure and leaves a rare one. The real protection
is `make observability-verify`, which compares live content and fires on the
symptom whatever caused it.

Each mounted directory therefore contains **only** files Prometheus should read
— a directory mount exposes everything in it, now and in future. That is why
`observability/` itself is not mountable (`grafana/provisioning/datasources/`
lives under it) and why `alerts_test.yml` deliberately stays in `observability/`
rather than moving into `rules/`: it is a `promtool` fixture, and Prometheus
would fail to parse it as a rule file.

Prometheus still needs a *signal* to re-read rules after an edit. The dev stack
runs with `--web.enable-lifecycle`, so `make observability-reload` applies a
change via `POST /-/reload` without recreating the container (and so without
dropping the in-memory TSDB head). `make observability-verify` then proves the
running process and the repo agree.

`talos-alerts.yaml` is **bind-mounted, never copied** — it is the same file the
chart's `PrometheusRule` embeds via `.Files.Get`, so the dev rules and the
production CRD cannot drift. (`deploy/observability/alerts.yaml` is a symlink to
it for the same reason.)

**Four of the five alerted `talos_*` `CounterVec`s are now pre-seeded at 0**
(2026-08-02). A prometheus `*Vec` exports nothing until some label set is
first touched, so on a healthy controller `talos_auth_attempts_total`,
`talos_kek_decrypt_failures_total`, `talos_memory_write_failures_total` and
`talos_module_payload_encryption_failures_total` were simply missing from
`/metrics/prometheus` — "detector absent" and "detector present and quiet"
were indistinguishable. Each now records `0` at registration for exactly the
label combinations a live call site writes:

| Series | Seeded values | Why that set |
|---|---|---|
| `talos_auth_attempts_total{method}` | `password`, `oauth` | the only two interactive-login emitters; `api_key` is deliberately not in this population |
| `talos_kek_decrypt_failures_total{provider}` | `active`, `both` | `legacy` has no emitting site anywhere — a flat 0 there would read as "watched" |
| `talos_memory_write_failures_total{reason}` | `crypto`, `db`, `validation`, `other` | the exhaustive `MemoryWriteError::metric_label()` match |
| `talos_module_payload_encryption_failures_total{op,stage}` | all 6 | both directions cover all three `PayloadSlot`s |

Note this makes the series PRESENT; it does not prove the incrementing call
site still exists. That is what check 58 and the per-metric unit tests are
for.

`talos_auth_failures_total{method,reason}` is the deliberate exception and
stays unseeded: only 9 of its 16 pairs have an emitting call site, and seeding
a pair nothing writes "would imply a wired signal that doesn't exist"
(#623's rule). Encoding the real pairing here would also mean duplicating
talos-auth's constants across a dependency edge that only points the other
way. Asserted in both directions by
`alerted_counter_vecs_are_seeded_at_zero_on_a_cold_registry` in
`talos-metrics`.

`TalosWorkerDown` is defined **once**, in `talos-alerts.yaml`. Until 2026-08-02
`observability/rules/alerts.yml` carried a second copy (`for: 1m`, `component=worker`
vs the canonical `for: 2m`, `category=availability`). That was invisible while
`docker-compose.yml` mounted no rules at all; mounting both files loaded both
copies and fired both on one worker outage — observed live. Alertmanager cannot
dedup them because the label sets differ, so it is two pages and two
contradictory runbook pointers for one incident. The dev copy was deleted and
structural lint **check 65(d)** now fails on any alert name defined in more than
one mounted rule file.

### rules/alerts.yml

WASM/worker alert rules (10 total).

> **Seven of the eleven rules that used to live here named a series the
> worker cannot emit under any workload** (found 2026-08-02). Two independent causes, both fixed:
>
> 1. **Wrong names.** These rules had been written against
>    `worker/src/bin/metrics_demo.rs` — a demo binary that fabricates
>    `wasm_*` data into its own private registry on port 9091, which is
>    exactly what this stack used to scrape. The real worker exports through
>    OpenTelemetry, and the exporter appends `_total` to every counter
>    UNCONDITIONALLY, so `wasm.executions.total` was rendered
>    `wasm_executions_total_total`. The instruments were renamed to drop the
>    redundant component; `wasm_cache_hits`/`_misses` were corrected to their
>    `_total` spellings; and `HighWASMMemoryUsage` was DELETED because
>    `wasm_memory_used_bytes` has no producer outside the demo binary.
>    `LowWASMThroughput` was deleted too — its 10 exec/sec floor came from
>    the demo's synthetic workload, and once the producer seeds at 0 it would
>    have sat permanently firing at `info` on every stack.
> 2. **Absence is not zero.** An OTEL instrument emits nothing until its
>    first measurement, so on an idle worker every `wasm_*` series was ABSENT
>    — and `rate(x[30m]) == 0` over an absent series matches NOTHING. The
>    alert built to detect "nothing is executing" was silenced by exactly the
>    condition it detects. `RuntimeMetrics::seed_zero_series` now records a 0
>    on the closed-label-set instruments at startup, and `NoWASMExecutions`
>    carries an `absent()` arm for the cases seeding cannot reach (a worker
>    too old to seed, a dead exporter, a renamed instrument).
>
> `OTEL_METRICS_ENABLED` is also now set for the worker in
> `docker-compose.yml`. It defaults to FALSE and the runtime skips building
> `RuntimeMetrics` entirely when unset, so before this the worker's
> `/metrics` was empty regardless of workload.
>
> `observability/alerts_test.yml` drives these transitions through
> `promtool test rules` (NOT CI-wired — there is no Prometheus toolchain on
> the runners; see its header).


**Performance Alerts** (5):
- HighWASMErrorRate (> 0.1 errors/sec)
- CriticalWASMErrorRate (> 1.0 errors/sec)
- SlowWASMExecution (P95 > 500ms)
- VerySlowWASMExecution (P95 > 2000ms)
- LowCacheHitRate (< 70%)

**Resource Alerts** (2):
- TooManyActiveInstances (> 500)
- HighRetryRate (> 0.5 retries/sec)
- ~~HighWASMMemoryUsage~~ — deleted; `wasm_memory_used_bytes` has no producer

**Service Health Alerts** (1):
- PrometheusScrapeFailure (any target down > 5m — broader than the per-job
  `TalosWorkerDown`/`TalosControllerDown`, which live in `talos-alerts.yaml`)

**Throughput Alerts** (1):
- NoWASMExecutions (`absent(...)` OR 30 min at a zero **summed** rate).
  The `sum()` is not cosmetic: `seed_zero_series` writes three `status`
  values, and a label-preserving `rate(...) == 0` turned one idle worker
  into THREE simultaneous alerts differing only by a label that means
  nothing here. Consequence for routing: **this alert carries no
  `job`/`instance`/`status` labels on either arm** — both yield the bare
  `{severity, component}` pair. An Alertmanager route or silence keyed on
  `instance` will not match it.
- ~~LowWASMThroughput~~ — deleted; a demo-derived SLO that would sit
  permanently firing once the producer seeds at 0

**Pipeline Liveness** (1):
- WASMMetricsPipelineDead — the worker target is UP but exports no
  `wasm_executions_total`. `up == 1` certifies reachability, NOT production.
  Gated on the target existing AND on the producer-side seeding, so it does
  not sit permanently red on a stack that is merely idle.

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

Edit `rules/alerts.yml`:

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

Reload Prometheus — and then prove the reload actually took effect:
```bash
make observability-reload   # POST /-/reload, then runs observability-verify
```

(`docker exec talos-prometheus kill -HUP 1` also reloads, but tells you
nothing about whether the running process now matches the repo.)

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

# Cache hit rate (%) — note the `_total` suffix the OTEL exporter appends
100 * rate(wasm_cache_hits_total[5m]) / (rate(wasm_cache_hits_total[5m]) + rate(wasm_cache_misses_total[5m]))

# Error rate by type
sum by (type) (rate(wasm_errors_total[5m]))

# Active instances
wasm_instances_active

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
