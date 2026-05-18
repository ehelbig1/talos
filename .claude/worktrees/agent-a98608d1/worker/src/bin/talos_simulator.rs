use anyhow::{Context, Result};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::Path;
use worker::runtime::TalosRuntime;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run --bin talos_simulator -- <path_to_wasm> [path_to_input_json]");
        eprintln!("Example: cargo run --bin talos_simulator -- module-templates/http-request/target/wasm32-wasip1/release/http_request.wasm input.json");
        std::process::exit(1);
    }

    let wasm_path = &args[1];
    let input_str = if args.len() > 2 {
        fs::read_to_string(&args[2]).unwrap_or_else(|_| "{}".to_string())
    } else {
        r#"{"config": {}, "input": {}}"#.to_string()
    };

    println!("🚀 Starting Talos WebAssembly Simulator...");
    println!("📦 Loading component: {}", wasm_path);

    let wasm_bytes = fs::read(wasm_path).context("Failed to read wasm file")?;

    // Attempt to automatically discover allowed_hosts from talos.json
    let mut allowed_hosts = vec![];
    let wasm_dir = Path::new(wasm_path)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let talos_json_path = wasm_dir.join("talos.json");
    if talos_json_path.exists() {
        if let Ok(manifest_str) = fs::read_to_string(&talos_json_path) {
            if let Ok(manifest) = serde_json::from_str::<Value>(&manifest_str) {
                if let Some(hosts) = manifest.get("allowed_hosts").and_then(|h| h.as_array()) {
                    for h in hosts {
                        if let Some(h_str) = h.as_str() {
                            allowed_hosts.push(h_str.to_string());
                        }
                    }
                    println!(
                        "🛡️  Loaded network permissions from talos.json: {:?}",
                        allowed_hosts
                    );
                }
            }
        }
    }

    if allowed_hosts.is_empty() {
        println!("⚠️  No allowed_hosts found in talos.json. Network requests will be blocked by the sandbox.");
    }

    let runtime = TalosRuntime::new()?;

    println!("▶️ Executing...");
    let start = std::time::Instant::now();

    let res = runtime
        .execute_job(
            &wasm_bytes,
            allowed_hosts,
            vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "PATCH".to_string(),
            ],
            50, // 50MB
            serde_json::from_str(&input_str).unwrap_or(serde_json::Value::Null),
        )
        .await;

    let duration = start.elapsed();

    match res {
        Ok(out) => {
            println!("\n✅ Execution succeeded in {:?}", duration);
            println!("Output:\n{}", serde_json::to_string_pretty(&out)?);
        }
        Err(e) => {
            eprintln!("\n❌ Execution failed after {:?}", duration);
            eprintln!("Error:\n{}", e);
        }
    }

    Ok(())
}
