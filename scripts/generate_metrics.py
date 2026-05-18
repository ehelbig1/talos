#!/usr/bin/env python3
"""
Simple metrics generator for Talos observability testing
Generates realistic WASM execution metrics for Prometheus/Grafana

Usage:
    python3 scripts/generate_metrics.py

Then view in Grafana at http://localhost:3001
"""

from prometheus_client import start_http_server, Counter, Histogram, Gauge
import random
import time
import sys

# Create metrics
executions_total = Counter(
    'wasm_executions_total',
    'Total number of WASM executions',
    ['status']
)

execution_duration = Histogram(
    'wasm_execution_duration_ms',
    'WASM execution duration in milliseconds',
    buckets=[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]
)

cache_hits = Counter('wasm_cache_hits', 'Number of WASM module cache hits')
cache_misses = Counter('wasm_cache_misses', 'Number of WASM module cache misses')

active_instances = Gauge('wasm_instances_active', 'Number of active WASM instances')
memory_used = Gauge('wasm_memory_used_bytes', 'Memory used by WASM instances in bytes')

errors_total = Counter(
    'wasm_errors_total',
    'Total number of WASM execution errors',
    ['type']
)

retries_total = Counter('wasm_retries_total', 'Total number of execution retries')

def generate_metrics():
    """Generate realistic metrics data"""
    iteration = 0

    print("=== Talos Metrics Generator ===\n")
    print("✅ Metrics server starting on port 9091")
    print("\n=== Observability URLs ===")
    print("  📊 Metrics:     http://localhost:9091/metrics")
    print("  📈 Prometheus:  http://localhost:9090")
    print("  📊 Grafana:     http://localhost:3001 (admin/admin)")
    print("  🔍 Jaeger:      http://localhost:16686")
    print("\n=== Generating Metrics ===\n")

    while True:
        iteration += 1

        # Simulate different execution scenarios
        scenario = random.randint(0, 9)

        if scenario <= 6:  # 70% success, cache hit
            executions_total.labels(status='success').inc()
            cache_hits.inc()
            execution_duration.observe(random.uniform(1, 50))

        elif scenario <= 8:  # 20% success, cache miss (slower)
            executions_total.labels(status='success').inc()
            cache_misses.inc()
            execution_duration.observe(random.uniform(50, 300))

        else:  # 10% errors
            executions_total.labels(status='failed').inc()
            error_types = ['OutOfMemory', 'Timeout', 'InvalidWASM', 'NetworkError']
            errors_total.labels(type=random.choice(error_types)).inc()
            execution_duration.observe(random.uniform(10, 100))

            # Sometimes retry
            if random.random() < 0.5:
                retries_total.inc()

        # Update gauges with some variation
        active_instances.set(random.randint(5, 25))
        memory_used.set(random.uniform(50_000_000, 200_000_000))  # 50-200 MB

        if iteration % 50 == 0:
            print(f"  📊 Generated {iteration} metric samples")

        # Generate metrics at ~10 per second
        time.sleep(0.1)

if __name__ == '__main__':
    try:
        # Start metrics HTTP server on port 9091
        start_http_server(9091)
        print("✅ Metrics server started successfully\n")

        # Generate metrics continuously
        generate_metrics()

    except KeyboardInterrupt:
        print("\n\n=== Shutting down ===")
        print("✅ Metrics generator stopped")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
