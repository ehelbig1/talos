use talos_sdk_macros::talos_module;

/// Pass upstream output through and inject `__memory_write__` so the
/// engine persists the payload to actor memory. `synced_at` is read
/// from upstream (`captured_at_ms` or `synced_at`) or falls back to
/// `0`; we deliberately avoid a wall-clock read so this module can
/// stay in the `minimal-node` world — no `env` / `datetime` host
/// imports required, and the compile environment does not need to
/// bundle `chrono`.
#[talos_module(world = "minimal-node")]
pub fn run(input: String) -> Result<String, String> {
    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let upstream = data.get("input").unwrap_or(&serde_json::Value::Null);
    let config = data.get("config").unwrap_or(&serde_json::Value::Null);

    let memory_key = config
        .get("MEMORY_KEY")
        .and_then(|v| v.as_str())
        .unwrap_or("work_context");
    let memory_type = config
        .get("MEMORY_TYPE")
        .and_then(|v| v.as_str())
        .unwrap_or("semantic");

    // Prefer a timestamp provided by the upstream payload so the
    // downstream memory value carries the time the data was *captured*,
    // not the time memory-writer happened to run. Falls back to the
    // WIT `datetime::now_unix()` host import (available in every
    // world including minimal-node) so memories always have a
    // meaningful wall-clock, not 0.
    let synced_at_ms: i64 = upstream
        .get("captured_at_ms")
        .and_then(|v| v.as_i64())
        .or_else(|| upstream.get("synced_at_ms").and_then(|v| v.as_i64()))
        .unwrap_or_else(|| (talos::core::datetime::now_unix() as i64).saturating_mul(1000));

    let memory_value = serde_json::json!({
        "data": upstream,
        "synced_at_ms": synced_at_ms,
        "source": "memory-writer",
    });

    let output = serde_json::json!({
        "__memory_write__": {
            "key": memory_key,
            "value": memory_value,
            "memory_type": memory_type,
        },
        "written_key": memory_key,
        "memory_type": memory_type,
        "synced_at_ms": synced_at_ms,
    });

    serde_json::to_string(&output).map_err(|e| e.to_string())
}
