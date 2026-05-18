use std::sync::Arc;
use worker::runtime::TalosRuntime;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let db_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect("postgres://talos:postgres@localhost:5433/talos")
        .await?;

    let runtime = Arc::new(TalosRuntime::with_resources(
        None,
        None,
        Some(db_pool),
        None,
    )?);

    let wasm_bytes = std::fs::read("/tmp/sandbox.wasm")?;
    let input = serde_json::json!({
        "config": {
            "query": "SELECT 1"
        },
        "input": null
    });

    let input_str = serde_json::to_string(&input)?;
    match runtime.execute_module_string(&wasm_bytes, &input_str).await {
        Ok(res) => println!("Raw Success: '{}'", res),
        Err(e) => println!("Raw Error: {:?}", e),
    }

    // We execute the module using the same function that fails in the controller
    match runtime
        .execute_job_with_full_features(
            &wasm_bytes,
            vec![],
            vec![],
            128,
            input,
            None,
            None,
            std::collections::HashMap::new(),
            None,
            std::time::Duration::from_secs(10),
            worker::runtime::RetryPolicy::default(),
            None,
        )
        .await
    {
        Ok(res) => println!("Success: {}", res),
        Err(e) => println!("Error: {:?}", e),
    }

    Ok(())
}
