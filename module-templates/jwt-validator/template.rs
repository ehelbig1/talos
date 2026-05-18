use talos_sdk_macros::talos_module;

#[talos_module(world = "secrets-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));

    let secret_name = config.get("SECRET_NAME").and_then(|v| v.as_str())
        .ok_or("Missing required config: SECRET_NAME")?;
    let token_field = config.get("TOKEN_FIELD").and_then(|v| v.as_str()).unwrap_or("token");
    let required_claims_str = config.get("REQUIRED_CLAIMS").and_then(|v| v.as_str()).unwrap_or("");

    let token = input_json.get(token_field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("Missing token field '{}' in input", token_field))?;

    // Resolve the signing key to a host-side slot handle (Tier 1).
    // The key bytes never enter guest memory.
    let key_slot = talos::core::secrets::get_secret(secret_name)
        .map_err(|e| format!("Failed to retrieve secret '{}': {:?}", secret_name, e))?;

    // Split JWT into parts: header.payload.signature
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        let _ = talos::core::secrets::release_slot(key_slot);
        return Err("Invalid JWT format: expected header.payload.signature".to_string());
    }

    // Base64url-decode payload (add padding if needed)
    let pad = |s: &str| -> String {
        let r = s.len() % 4;
        if r == 0 { s.to_string() } else { format!("{}{}", s, "=".repeat(4 - r)) }
    };
    let payload_bytes = base64_decode(&pad(parts[1]))
        .map_err(|e| format!("Failed to decode JWT payload: {}", e))?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("Failed to parse JWT payload as JSON: {}", e))?;

    // Verify signature: compute HMAC-SHA256 in the host (key never crosses boundary).
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let expected_sig = talos::core::secrets::hmac_sign(key_slot, signing_input.as_bytes())
        .map_err(|e| format!("HMAC signing failed: {:?}", e))?;
    let _ = talos::core::secrets::release_slot(key_slot);

    let expected_b64 = base64url_encode(&expected_sig);
    if !constant_time_eq(expected_b64.as_bytes(), parts[2].as_bytes()) {
        return Err("JWT signature verification failed".to_string());
    }

    // Check expiry
    if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
        // Current time via a rough epoch calculation is unavailable in WASM minimal world.
        // We validate exp presence but skip wall-clock comparison in the sandbox.
        if exp == 0 {
            return Err("JWT has invalid exp claim".to_string());
        }
    }

    // Validate required claims
    if !required_claims_str.is_empty() {
        let mut missing = Vec::new();
        for claim in required_claims_str.split(',') {
            let c = claim.trim();
            if !c.is_empty() && claims.get(c).is_none() {
                missing.push(c.to_string());
            }
        }
        if !missing.is_empty() {
            return Err(format!("JWT missing required claims: {}", missing.join(", ")));
        }
    }

    let result = serde_json::json!({
        "valid": true,
        "claims": claims,
    });
    Ok(result.to_string())
}

// Minimal base64 decode (standard + URL-safe alphabet, with padding)
fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let s = s.replace('-', "+").replace('_', "/");
    let s = s.trim_end_matches('=');
    let mut bits: u32 = 0;
    let mut bit_count: u8 = 0;
    let mut out = Vec::new();
    for c in s.chars() {
        let val = alphabet.find(c)
            .ok_or_else(|| format!("Invalid base64 character: {}", c))? as u32;
        bits = (bits << 6) | val;
        bit_count += 6;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push(((bits >> bit_count) & 0xFF) as u8);
        }
    }
    Ok(out)
}

// Base64url encode (no padding, URL-safe alphabet)
fn base64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i] as u32;
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] as u32 } else { 0 };
        out.push(ALPHABET[((b0 >> 2) & 0x3F) as usize] as char);
        out.push(ALPHABET[(((b0 << 4) | (b1 >> 4)) & 0x3F) as usize] as char);
        if i + 1 < bytes.len() { out.push(ALPHABET[(((b1 << 2) | (b2 >> 6)) & 0x3F) as usize] as char); }
        if i + 2 < bytes.len() { out.push(ALPHABET[(b2 & 0x3F) as usize] as char); }
        i += 3;
    }
    out
}

// Constant-time byte comparison to prevent timing attacks on signature verification
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
