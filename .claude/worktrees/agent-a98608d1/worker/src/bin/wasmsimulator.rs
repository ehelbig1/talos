use sqlx::postgres::PgPoolOptions;
use std::collections::HashMap;
use uuid::Uuid;
use worker::runtime::{PipelineStepSpec, TalosRuntime};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let pool = PgPoolOptions::new()
        .connect("postgres://talos:postgres@localhost:5433/talos")
        .await?;

    let row = sqlx::query(
        "SELECT wasm_bytes FROM wasm_modules WHERE id = '5fdf3c2f-131d-4c88-9a75-35cada9c2a7e'",
    )
    .fetch_one(&pool)
    .await?;

    let wasm_bytes: Vec<u8> = sqlx::Row::get(&row, "wasm_bytes");
    println!("WASM length: {}", wasm_bytes.len());
    println!(
        "WASM first 16 bytes: {:?}",
        &wasm_bytes[0..16.min(wasm_bytes.len())]
    );

    // 1. Initialize the Wasmtime engine
    let runtime = TalosRuntime::new()?;

    // 2. Load the component WASM we built inside the controller container
    // let wasm_bytes = std::fs::read("/tmp/test_comp.wasm")?; // This line is replaced by the sqlx query

    // 3. Prepare the step mimicking the controller
    let step = PipelineStepSpec {
        module_id: "test-module".into(),
        wasm_bytes,
        config: serde_json::json!({
            "pipeline_input": {},
            "config": {
                "repo": "talos",
                "pull_number": 1
            }
        }),
        allowed_hosts: vec![],
        allowed_methods: vec![],
        secrets: HashMap::new(),
        max_fuel: 1_000_000,
        max_memory_mb: 128,
        timeout: std::time::Duration::from_secs(30),
    };

    println!("Executing pipeline step...");

    // 4. Run it
    let result = runtime
        .execute_pipeline(
            &Uuid::new_v4().to_string(),
            vec![step],
            std::time::Duration::from_secs(30),
            false,
        )
        .await;

    match result {
        Ok(res) => println!("SUCCESS: {:?}", res.final_output),
        Err(e) => {
            println!("ERROR: {:?}", e);
            e.chain().for_each(|cause| println!("Caused by: {}", cause));
        }
    }

    Ok(())
}
