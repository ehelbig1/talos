/// Simple Metrics Demo for Observability Testing
/// Generates sample metrics and traces without requiring full WASM runtime
///
/// Usage:
///   cargo run --bin metrics_demo
///
/// This will:
/// - Start metrics server on port 9090
/// - Generate sample metric data
/// - Send traces to Jaeger (if available)
use std::time::Duration;
use tokio::time::sleep;

// Import only what we need
use prometheus::{Counter, Encoder, Gauge, Histogram, Registry, TextEncoder};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Talos Metrics Demo ===\n");

    // Create Prometheus registry
    let registry = Registry::new();

    // Create metrics
    let executions = Counter::new("wasm_executions_total", "Total number of WASM executions")?;
    registry.register(Box::new(executions.clone()))?;

    let execution_duration = Histogram::with_opts(
        prometheus::HistogramOpts::new(
            "wasm_execution_duration_ms",
            "WASM execution duration in milliseconds",
        )
        .buckets(vec![
            1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
        ]),
    )?;
    registry.register(Box::new(execution_duration.clone()))?;

    let cache_hits = Counter::new("wasm_cache_hits", "Number of WASM module cache hits")?;
    registry.register(Box::new(cache_hits.clone()))?;

    let cache_misses = Counter::new("wasm_cache_misses", "Number of WASM module cache misses")?;
    registry.register(Box::new(cache_misses.clone()))?;

    let active_instances = Gauge::new("wasm_instances_active", "Number of active WASM instances")?;
    registry.register(Box::new(active_instances.clone()))?;

    let memory_used = Gauge::new(
        "wasm_memory_used_bytes",
        "Memory used by WASM instances in bytes",
    )?;
    registry.register(Box::new(memory_used.clone()))?;

    let errors = Counter::new("wasm_errors_total", "Total number of WASM execution errors")?;
    registry.register(Box::new(errors.clone()))?;

    println!("✅ Metrics registered");

    // Start simple HTTP server for metrics
    let registry_clone = Arc::new(registry);
    let server_registry = registry_clone.clone();

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:9091").await.unwrap();
        println!("📊 Metrics server listening on http://0.0.0.0:9091/metrics");

        loop {
            // `socket` does not need to be mutable; removing `mut` silences the warning.
            if let Ok((socket, _)) = listener.accept().await {
                let registry = server_registry.clone();
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 1024];
                    let n = match socket.try_read(&mut buffer) {
                        Ok(n) => n,
                        Err(_) => return,
                    };

                    let request = String::from_utf8_lossy(&buffer[..n]);
                    if request.contains("GET /metrics") {
                        let encoder = TextEncoder::new();
                        let metric_families = registry.gather();
                        let mut buffer = vec![];
                        encoder.encode(&metric_families, &mut buffer).unwrap();
                        let metrics = String::from_utf8(buffer).unwrap();

                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                            metrics.len(),
                            metrics
                        );
                        let _ = socket.try_write(response.as_bytes());
                    } else if request.contains("GET /health") {
                        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK";
                        let _ = socket.try_write(response.as_bytes());
                    }
                });
            }
        }
    });

    println!("\n=== Observability Stack Ready ===");
    println!("  📊 Metrics:     http://localhost:9091/metrics");
    println!("  💚 Health:      http://localhost:9091/health");
    println!("  📈 Prometheus:  http://localhost:9090");
    println!("  📊 Grafana:     http://localhost:3001 (admin/admin)");
    println!("  🔍 Jaeger:      http://localhost:16686");
    println!();

    // Wait for server to start
    sleep(Duration::from_secs(1)).await;

    println!("=== Generating Sample Metrics ===");
    println!("Running continuous test workload...\n");

    let mut iteration = 0;
    loop {
        iteration += 1;

        // Simulate different execution scenarios
        let scenario = iteration % 10;

        match scenario {
            0..=6 => {
                // Success cases (70%)
                executions.inc();
                cache_hits.inc();
                execution_duration.observe((iteration % 50) as f64);
                active_instances.set((iteration % 20) as f64);
                memory_used.set((iteration % 100) as f64 * 1024.0 * 1024.0);
            }
            7..=8 => {
                // Cache miss (20%)
                executions.inc();
                cache_misses.inc();
                execution_duration.observe((100 + iteration % 150) as f64);
                active_instances.set((iteration % 20) as f64);
                memory_used.set((iteration % 100) as f64 * 1024.0 * 1024.0);
            }
            _ => {
                // Error (10%)
                errors.inc();
                execution_duration.observe(50.0);
            }
        }

        if iteration % 10 == 0 {
            println!("  📊 Generated {} metrics", iteration);
        }

        // Delay between metrics
        sleep(Duration::from_millis(100)).await;
    }
}
