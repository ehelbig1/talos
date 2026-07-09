use std::sync::Arc;
use worker::runtime::TalosRuntime;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Worker is credential-free as of Phase 2.10; database access flows
    // through signed NATS-RPC to the controller. No PgPool here.
    let runtime = Arc::new(TalosRuntime::with_resources(None, None, None)?);

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
            worker::runtime::SecurityPolicy::default(),
            None,                                             // capability_world_hint
            None,                                             // max_fuel_override
            false,                                            // dry_run
            None,                                             // actor_id
            uuid::Uuid::nil(),                                // user_id
            talos_workflow_job_protocol::LlmTier::Tier2,      // max_llm_tier
            talos_workflow_job_protocol::WriteCeiling::Write, // max_write_ceiling
        )
        .await
    {
        Ok(res) => println!("Success: {}", res),
        Err(e) => println!("Error: {:?}", e),
    }

    Ok(())
}
