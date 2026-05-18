use talos_sdk_macros::talos_module;

#[talos_module(world = "secrets-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));

    let secret_name = config.get("SECRET_NAME").and_then(|v| v.as_str())
        .ok_or("Missing required config: SECRET_NAME")?;
    let data_field = config.get("DATA_FIELD").and_then(|v| v.as_str()).unwrap_or("data");
    let prefix = config.get("INCLUDE_PREFIX").and_then(|v| v.as_str()).unwrap_or("");

    let data = input_json.get(data_field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("Missing field '{}' in input", data_field))?;

    // Resolve the signing key to a host-side slot handle (Tier 1).
    // The key bytes never enter guest memory — the host performs the HMAC internally.
    let key_slot = talos::core::secrets::get_secret(secret_name)
        .map_err(|e| format!("Failed to retrieve secret '{}': {:?}", secret_name, e))?;

    // hmac_sign delegates to the host: key stays in the DashMap slot, only the
    // signature bytes cross the WASM boundary (which is safe — HMAC output is public).
    let sig_bytes = talos::core::secrets::hmac_sign(key_slot, data.as_bytes())
        .map_err(|e| format!("HMAC signing failed: {:?}", e))?;
    let _ = talos::core::secrets::release_slot(key_slot);

    let hex_sig: String = sig_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let signature = format!("{}{}", prefix, hex_sig);

    let result = serde_json::json!({
        "signature": signature,
        "algorithm": "HMAC-SHA256",
        "data_field": data_field,
    });
    Ok(result.to_string())
}
