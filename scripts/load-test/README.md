# Talos Load Testing

Load tests for the Talos platform using [k6](https://grafana.com/docs/k6/latest/) by Grafana Labs.

## Prerequisites

### Install k6

**macOS:**
```bash
brew install k6
```

**Linux (Debian/Ubuntu):**
```bash
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
  --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D68
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update && sudo apt-get install k6
```

**Docker:**
```bash
docker pull grafana/k6
```

**Verify installation:**
```bash
k6 version
```

## Test Scripts

### 1. GraphQL API Load Test (`graphql-api.js`)

Exercises the core GraphQL API endpoints under load:
- **Login** -- authenticates a test user
- **List Workflows** -- paginated query
- **Create Workflow** -- mutation with graph JSON payload
- **Trigger Execution** -- starts a workflow execution
- **List Secrets** -- paginated secrets query

**Default profile:** ramp 0 -> 20 -> 50 -> 100 -> 0 VUs over ~2.5 minutes.

```bash
# Run with defaults (targets localhost:8080)
k6 run scripts/load-test/graphql-api.js

# Target a specific environment
k6 run --env BASE_URL=https://talos.staging.example.com scripts/load-test/graphql-api.js

# Custom test user credentials
k6 run --env TEST_EMAIL=perf@example.com --env TEST_PASSWORD=secret123 scripts/load-test/graphql-api.js

# Adjust load profile
k6 run --env VUS=100 --env VUS_PEAK=200 --env SUSTAIN=3m scripts/load-test/graphql-api.js
```

### 2. Workflow Execution Pipeline Test (`workflow-execution.js`)

Stress-tests the full workflow execution lifecycle with three concurrent scenarios:
1. **Sustained execution** -- 10 VUs continuously listing workflows and triggering executions for 2 minutes
2. **Burst trigger** -- ramps to 50 VUs firing concurrent execution triggers to stress the pipeline
3. **Health check** -- 100 req/s constant rate against the health endpoint for the full duration

```bash
# Run with defaults (targets localhost:8080)
k6 run scripts/load-test/workflow-execution.js

# Target a specific environment
k6 run --env BASE_URL=https://talos.staging.example.com scripts/load-test/workflow-execution.js

# Custom credentials
k6 run --env TEST_EMAIL=perf@example.com --env TEST_PASSWORD=secret123 scripts/load-test/workflow-execution.js

# Adjust load profile
k6 run --env SUSTAINED_VUS=20 --env BURST_PEAK=100 --env HEALTH_RPS=200 scripts/load-test/workflow-execution.js
```

### 3. Webhook Throughput Test (`webhook-throughput.js`)

Tests webhook ingestion performance with two scenarios:
1. **Sustained throughput** -- constant 50 req/s for 2 minutes
2. **Rate-limit spike** -- ramps to 200 req/s to verify rate limiting kicks in

```bash
# Run with a real webhook ID
k6 run --env WEBHOOK_ID=<your-webhook-uuid> scripts/load-test/webhook-throughput.js

# With HMAC secret for authenticated webhooks
k6 run \
  --env WEBHOOK_ID=<uuid> \
  --env WEBHOOK_SECRET=<secret> \
  scripts/load-test/webhook-throughput.js

# Adjust throughput
k6 run --env RPS=100 --env DURATION=5m scripts/load-test/webhook-throughput.js
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `BASE_URL` | `http://localhost:8080` | Target server URL |
| `TEST_EMAIL` | `loadtest@example.com` | Test user email (graphql-api.js) |
| `TEST_PASSWORD` | `LoadTest!2026` | Test user password (graphql-api.js) |
| `VUS` | `50` | Sustained virtual users |
| `VUS_PEAK` | `100` | Peak virtual users |
| `VUS_RAMP` | `20` | Ramp-up target VUs |
| `RAMP_UP` | `30s` | Ramp-up duration |
| `SUSTAIN` | `1m` | Sustained load duration |
| `PEAK` | `30s` | Peak load duration |
| `RAMP_DOWN` | `30s` | Ramp-down duration |
| `SUSTAINED_VUS` | `10` | Sustained VUs (workflow-execution.js) |
| `SUSTAINED_DURATION` | `2m` | Sustained phase duration (workflow-execution.js) |
| `BURST_PEAK` | `50` | Peak VUs for burst phase (workflow-execution.js) |
| `HEALTH_RPS` | `100` | Health check requests/sec (workflow-execution.js) |
| `WEBHOOK_ID` | placeholder UUID | Webhook trigger ID |
| `WEBHOOK_SECRET` | empty | HMAC secret for webhook signing |
| `RPS` | `50` | Requests per second (webhook test) |
| `DURATION` | `2m` | Test duration (webhook test) |
| `MAX_VUS` | `100` | Max VUs (webhook test) |

## Interpreting Results

### Key Metrics

After each test run, k6 prints a summary. Focus on these metrics:

| Metric | Meaning | Healthy Threshold |
|---|---|---|
| `http_req_duration (p95)` | 95th percentile response time | < 500ms |
| `http_req_failed` | Percentage of failed HTTP requests | < 1% |
| `login_duration (p95)` | Login operation latency | < 1s |
| `list_workflows_duration (p95)` | Workflow listing latency | < 300ms |
| `workflow_execution_duration (p95)` | Workflow trigger latency | < 5s |
| `workflow_success_rate` | Successful execution rate | > 95% |
| `executions_triggered` | Total executions triggered | informational |
| `webhook_latency (p95)` | Webhook acceptance latency | < 200ms |
| `webhook_rate_limited` | Count of 429 responses | > 0 during spike test |
| `graphql_errors` | Total GraphQL-level errors | < 100 |

### Threshold Failures

If any threshold fails, k6 exits with code 99. A summary table marks failing thresholds with a cross. Common causes:

- **`http_req_duration` too high** -- backend overloaded, check DB connection pool and query performance
- **`http_req_failed` too high** -- server errors under load, check logs for panics or OOM
- **`auth_failures` too high** -- rate limiter may be too aggressive, or test user credentials are wrong
- **`webhook_rate_limited` is zero during spike** -- rate limiter may not be configured

### Output Formats

Export results for dashboards:

```bash
# JSON output
k6 run --out json=results.json scripts/load-test/graphql-api.js

# CSV output
k6 run --out csv=results.csv scripts/load-test/graphql-api.js

# InfluxDB (for Grafana dashboards)
k6 run --out influxdb=http://localhost:8086/k6 scripts/load-test/graphql-api.js
```

## Pre-Test Checklist

1. Ensure the target environment is running (`curl $BASE_URL/health`)
2. Create a dedicated load-test user account if testing against a real environment
3. For webhook tests, create a webhook trigger and note the ID
4. Verify the test user has appropriate permissions (workflows:read, workflows:write, secrets:read)
5. Monitor server resources (CPU, memory, DB connections) during the test
6. Run from a machine with low network latency to the target to get accurate latency measurements
