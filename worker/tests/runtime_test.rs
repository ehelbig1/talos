use serde_json::json;
use std::time::Duration;
use talos_workflow_job_protocol::LlmTier;
use uuid::Uuid;
use worker::runtime::{RetryPolicy, SecurityPolicy, TalosRuntime};

#[tokio::test]
async fn test_runtime_no_nested_block_on() {
    let runtime = TalosRuntime::new().expect("Failed to create runtime");

    // We'll use a dummy buffer that isn't valid WASM.
    // The key is that execute_job_with_full_features is an async function
    // and we are calling it from a tokio::test (which has a runtime).
    // If it internally uses block_on, it will panic before even validating the WASM.
    let wasm = b"\0asm\x01\0\0\0";

    let result = runtime
        .execute_job_with_full_features(
            wasm,
            vec![],
            vec![],
            128,
            json!({"test": true}),
            None,
            None,
            std::collections::HashMap::new(),
            None,
            Duration::from_secs(1),
            RetryPolicy::none(),
            None,
            SecurityPolicy::default(),
            None,           // capability_world_hint
            None,           // max_fuel_override
            false,          // dry_run
            None,           // actor_id
            Uuid::nil(),    // user_id
            LlmTier::Tier2, // max_llm_tier
        )
        .await;

    // It should fail with a WASM validation error, NOT a runtime panic.
    assert!(result.is_err());
    let err_str = format!("{:?}", result.err());
    assert!(
        !err_str.contains("Cannot start a runtime from within a runtime"),
        "Detected nested block_on panic!"
    );
}
