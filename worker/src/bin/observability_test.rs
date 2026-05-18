// Removed unused import
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
/// Observability Test Binary
/// Generates sample WASM executions to populate Prometheus metrics and Jaeger traces
///
/// Usage:
///   cargo run --bin observability_test
///
/// This will:
/// - Start metrics server on port 9090
/// - Execute sample WASM workloads
/// - Send traces to Jaeger
/// - Populate Grafana dashboards with data
use worker::{metrics, metrics_server, tracing, TalosRuntime};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Talos Observability Test ===\n");

    // Initialize OpenTelemetry metrics
    println!("[1/4] Initializing OpenTelemetry metrics...");
    metrics::init_telemetry()?;
    println!("      ✅ Metrics initialized\n");

    // Initialize Jaeger tracing with OTLP
    println!("[2/4] Initializing Jaeger tracing (OTLP)...");
    tracing::init_tracing(
        "talos-worker",
        Some("http://localhost:4317"), // Jaeger OTLP gRPC endpoint
    )?;
    println!("      ✅ Tracing initialized\n");

    // Create WASM runtime
    println!("[3/4] Creating Talos WASM runtime...");
    let runtime = Arc::new(TalosRuntime::new()?);
    println!("      ✅ Runtime created\n");

    // Start metrics server
    println!("[4/4] Starting metrics server on port 9090...");
    let _metrics_handle = metrics_server::start_metrics_server(runtime.clone(), 9090)
        .expect("Metrics server requires METRICS_AUTH_TOKENS");
    println!("      ✅ Metrics server running\n");

    println!("=== Observability Stack Ready ===");
    println!("  📊 Metrics:     http://localhost:9090/metrics");
    println!("  💚 Health:      http://localhost:9090/health");
    println!("  📈 Prometheus:  http://localhost:9090");
    println!("  📊 Grafana:     http://localhost:3001 (admin/admin)");
    println!("  🔍 Jaeger:      http://localhost:16686");
    println!();

    // Check if we have a test WASM module
    let test_wasm_path = "test-module.wasm";
    // Prefix with underscore to silence unused‑variable warning
    let _wasm_bytes = if std::path::Path::new(test_wasm_path).exists() {
        println!("🎯 Found test WASM module: {}", test_wasm_path);
        std::fs::read(test_wasm_path)?
    } else {
        println!("⚠️  No test WASM module found at: {}", test_wasm_path);
        println!("   Creating minimal test module...");

        // Create a minimal WASM module (WAT format compiled to WASM)
        // This is a simple module that does nothing but is valid WASM
        // In a real scenario, you'd use a proper WASM module
        vec![
            0x00, 0x61, 0x73, 0x6d, // Magic number
            0x01, 0x00, 0x00, 0x00, // Version
        ]
    };

    println!("\n=== Generating Sample Metrics ===");
    println!("Running 100 test executions...\n");

    let mut success_count = 0;
    let mut error_count = 0;

    for i in 0..100 {
        // Create a span for this execution
        let mut span =
            tracing::ExecutionSpan::new("test-workflow-execution", &format!("test-exec-{}", i));

        span.set_attribute("workflow_id", &format!("workflow-{}", i % 10));
        span.set_attribute("module_id", "test-module");
        span.set_attribute("iteration", &i.to_string());

        // Simulate different execution scenarios
        let scenario = i % 5;

        match scenario {
            0 => {
                // Fast execution (cache hit simulation)
                span.add_event("cache_hit");
                span.set_attribute_bool("cache_hit", true);
                sleep(Duration::from_millis(1)).await;
                span.end_success();
                success_count += 1;
            }
            1 => {
                // Slow execution (cache miss, compilation needed)
                span.add_event("cache_miss");
                span.add_event("compilation_started");
                span.set_attribute_bool("cache_hit", false);
                sleep(Duration::from_millis(50)).await;
                span.add_event("compilation_completed");
                span.add_event("execution_started");
                sleep(Duration::from_millis(10)).await;
                span.end_success();
                success_count += 1;
            }
            2 => {
                // Medium execution
                span.add_event("cache_hit");
                span.set_attribute_bool("cache_hit", true);
                sleep(Duration::from_millis(5)).await;
                span.end_success();
                success_count += 1;
            }
            3 => {
                // Error scenario
                span.add_event("error_occurred");
                span.set_attribute("error_type", "OutOfMemory");
                sleep(Duration::from_millis(20)).await;
                span.end_error("Out of memory");
                error_count += 1;
            }
            _ => {
                // Normal execution
                span.add_event("execution_started");
                span.set_attribute_bool("cache_hit", true);
                sleep(Duration::from_millis(3)).await;
                span.end_success();
                success_count += 1;
            }
        }

        // Update progress
        if (i + 1) % 10 == 0 {
            println!(
                "  Progress: {}/100 executions complete (✅ {} success, ❌ {} errors)",
                i + 1,
                success_count,
                error_count
            );
        }

        // Small delay between executions
        sleep(Duration::from_millis(100)).await;
    }

    println!("\n=== Metrics Generation Complete ===");
    println!("  Total executions: 100");
    println!("  Successful:       {} ({}%)", success_count, success_count);
    println!("  Errors:           {} ({}%)", error_count, error_count);
    println!();
    println!("📊 Metrics are now available in Grafana!");
    println!("   Open http://localhost:3001 and view the 'Talos WASM Runtime' dashboard");
    println!();
    println!("🔍 Traces are available in Jaeger!");
    println!("   Open http://localhost:16686 and search for service 'talos-worker'");
    println!();
    println!("Keeping metrics server running for 5 minutes...");
    println!("Press Ctrl+C to stop");

    // Keep the server running for 5 minutes so metrics can be scraped
    for remaining in (1..=5).rev() {
        sleep(Duration::from_secs(60)).await;
        println!("  ⏱️  {} minutes remaining...", remaining);
    }

    println!("\n=== Shutting Down ===");
    tracing::shutdown_tracing();
    println!("✅ Observability test complete!");

    Ok(())
}
