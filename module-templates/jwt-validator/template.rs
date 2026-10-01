use talos_sdk_macros::talos_module;

#[talos_module(world = "secrets-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value = serde_json::from_str(&input).unwrap_or(serde_json::json!({}));
    let config = input_json.get("config").cloned().unwrap_or(serde_json::json!({}));

    let secret_name = config.get("SECRET_NAME").and_then(|v| v.as_str())
        .ok_or("Missing required config: SECRET_NAME")?;
    let token_field = config.get("TOKEN_FIELD").and_then(|v| v.as_str()).unwrap_or("token");
    let required_claims_str = config.get("REQUIRED_CLAIMS").and_then(|v| v.as_str()).unwrap_or("");
    // ALGORITHM is documented with a single supported value. A node that
    // asks for another must be told, not verified as HS256 without a word.
    if let Some(alg) = config.get("ALGORITHM") {
        if !alg.is_null() && alg.as_str() != Some("HS256") {
            return Err("ALGORITHM: only HS256 is supported".to_string());
        }
    }
    let allow_no_expiry = config.get("ALLOW_NO_EXPIRY").and_then(|v| v.as_bool()).unwrap_or(false);
    let leeway_secs = leeway_secs(config.get("LEEWAY_SECS"))?;

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

    // Everything below reads a token whose signature has been verified.

    // The header must name the one algorithm this module verifies. The
    // signature check above is always HMAC-SHA256 whatever the header says,
    // so this is not what stops a forged token; it refuses a token whose
    // issuer signs with something else rather than calling it valid.
    let header_bytes = base64_decode(&pad(parts[0]))
        .map_err(|e| format!("Failed to decode JWT header: {}", e))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| format!("Failed to parse JWT header as JSON: {}", e))?;
    check_algorithm(&header)?;

    // Expiry and not-before, against the wall clock.
    check_time_claims(&claims, now_secs()?, leeway_secs, allow_no_expiry)?;

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

/// Seconds of clock skew tolerated on `exp` and `nbf` when unset.
const DEFAULT_LEEWAY_SECS: i64 = 60;
/// Largest leeway a node may configure.
const MAX_LEEWAY_SECS: i64 = 300;

/// `LEEWAY_SECS` from config: absent → the default; otherwise a whole number
/// of seconds from 0 to `MAX_LEEWAY_SECS`. Anything else is an error — a
/// typo must not silently widen how long an expired token is accepted.
fn leeway_secs(value: Option<&serde_json::Value>) -> Result<i64, String> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(DEFAULT_LEEWAY_SECS),
        Some(v) => match v.as_i64() {
            Some(n) if (0..=MAX_LEEWAY_SECS).contains(&n) => Ok(n),
            _ => Err(format!(
                "LEEWAY_SECS must be a whole number of seconds from 0 to {MAX_LEEWAY_SECS}"
            )),
        },
    }
}

/// Seconds since the Unix epoch. An unreadable clock is an error: a token's
/// lifetime cannot be judged without one, and the answer must not be "valid".
fn now_secs() -> Result<i64, String> {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "System clock is before the Unix epoch; cannot check token lifetime".to_string())?;
    i64::try_from(since_epoch.as_secs())
        .map_err(|_| "System clock out of range; cannot check token lifetime".to_string())
}

/// The header's `alg` must be `HS256`, the only algorithm verified here.
fn check_algorithm(header: &serde_json::Value) -> Result<(), String> {
    match header.get("alg").and_then(|a| a.as_str()) {
        Some("HS256") => Ok(()),
        Some(other) => Err(format!(
            "JWT algorithm '{}' is not supported (only HS256)",
            other.chars().take(16).collect::<String>()
        )),
        None => Err("JWT header has no 'alg'".to_string()),
    }
}

/// A NumericDate claim (RFC 7519 §2): a JSON number of seconds since the
/// epoch, possibly fractional. `Ok(None)` when the claim is absent;
/// an error when it is present and not a finite number.
fn numeric_date(claims: &serde_json::Value, name: &str) -> Result<Option<f64>, String> {
    match claims.get(name) {
        None => Ok(None),
        Some(v) => match v.as_f64() {
            Some(n) if n.is_finite() => Ok(Some(n)),
            _ => Err(format!("JWT '{name}' claim is not a number")),
        },
    }
}

/// Refuse a token that has expired, is not yet valid, or carries no expiry.
///
/// * `exp` present: the token is refused from `exp + leeway` onward.
/// * `exp` absent: refused unless `allow_no_expiry` — a token with no expiry
///   is valid forever, which a caller must choose, not get by default.
/// * `nbf` present: refused until `nbf - leeway`.
fn check_time_claims(
    claims: &serde_json::Value,
    now: i64,
    leeway: i64,
    allow_no_expiry: bool,
) -> Result<(), String> {
    let now = now as f64;
    let leeway = leeway as f64;
    match numeric_date(claims, "exp")? {
        Some(exp) => {
            if now >= exp + leeway {
                return Err("JWT has expired".to_string());
            }
        }
        None => {
            if !allow_no_expiry {
                return Err(
                    "JWT has no 'exp' claim; set ALLOW_NO_EXPIRY: true to accept a token that never expires"
                        .to_string(),
                );
            }
        }
    }
    if let Some(nbf) = numeric_date(claims, "nbf")? {
        if now + leeway < nbf {
            return Err("JWT is not yet valid ('nbf' is in the future)".to_string());
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;

    #[test]
    fn an_expired_token_is_refused_and_a_live_one_accepted() {
        // Live: expires in an hour.
        assert!(check_time_claims(&json!({"exp": NOW + 3600}), NOW, 60, false).is_ok());
        // Expired an hour ago.
        assert_eq!(
            check_time_claims(&json!({"exp": NOW - 3600}), NOW, 60, false),
            Err("JWT has expired".to_string())
        );
        // Expired a hundred years ago, the case the old code called valid.
        assert!(check_time_claims(&json!({"exp": 1}), NOW, 60, false).is_err());
    }

    #[test]
    fn the_leeway_is_exact_at_its_boundary() {
        // exp + leeway is the first refused second.
        assert!(check_time_claims(&json!({"exp": NOW - 59}), NOW, 60, false).is_ok());
        assert!(check_time_claims(&json!({"exp": NOW - 60}), NOW, 60, false).is_err());
        // No leeway: refused at exp itself.
        assert!(check_time_claims(&json!({"exp": NOW + 1}), NOW, 0, false).is_ok());
        assert!(check_time_claims(&json!({"exp": NOW}), NOW, 0, false).is_err());
    }

    #[test]
    fn a_token_with_no_expiry_is_refused_unless_the_node_opts_in() {
        assert!(check_time_claims(&json!({"sub": "a"}), NOW, 60, false).is_err());
        assert!(check_time_claims(&json!({"sub": "a"}), NOW, 60, true).is_ok());
        // Opting in does not excuse an expiry that is present and past.
        assert!(check_time_claims(&json!({"exp": NOW - 3600}), NOW, 60, true).is_err());
    }

    #[test]
    fn an_exp_that_is_not_a_number_is_refused_not_ignored() {
        for bad in [json!("1800003600"), json!(null), json!(true), json!([1]), json!({})] {
            let claims = json!({"exp": bad});
            assert!(check_time_claims(&claims, NOW, 60, false).is_err(), "{claims}");
            // Not rescued by ALLOW_NO_EXPIRY either: the claim is present.
            assert!(check_time_claims(&claims, NOW, 60, true).is_err(), "{claims}");
        }
        // A fractional NumericDate is legal.
        assert!(check_time_claims(&json!({"exp": (NOW + 10) as f64 + 0.5}), NOW, 0, false).is_ok());
    }

    #[test]
    fn a_token_not_yet_valid_is_refused() {
        let live = NOW + 3600;
        assert!(check_time_claims(&json!({"exp": live, "nbf": NOW - 10}), NOW, 60, false).is_ok());
        assert!(check_time_claims(&json!({"exp": live, "nbf": NOW + 60}), NOW, 60, false).is_ok());
        assert!(check_time_claims(&json!({"exp": live, "nbf": NOW + 61}), NOW, 60, false).is_err());
        assert!(check_time_claims(&json!({"exp": live, "nbf": "soon"}), NOW, 60, false).is_err());
    }

    #[test]
    fn only_hs256_is_accepted_in_the_header() {
        assert!(check_algorithm(&json!({"alg": "HS256", "typ": "JWT"})).is_ok());
        for bad in [json!({"alg": "none"}), json!({"alg": "RS256"}), json!({"alg": "hs256"}), json!({"typ": "JWT"}), json!({"alg": 1})] {
            assert!(check_algorithm(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_bad_leeway_is_an_error_not_a_wider_window() {
        assert_eq!(leeway_secs(None), Ok(60));
        assert_eq!(leeway_secs(Some(&json!(0))), Ok(0));
        assert_eq!(leeway_secs(Some(&json!(300))), Ok(300));
        for bad in [json!(301), json!(-1), json!("60"), json!(1.5), json!(86_400)] {
            assert!(leeway_secs(Some(&bad)).is_err(), "{bad}");
        }
    }

    // ── The whole module, with a real HMAC behind the stubbed host ─────────

    fn token(header: serde_json::Value, claims: serde_json::Value, key: &[u8]) -> String {
        let h = base64url_encode(header.to_string().as_bytes());
        let p = base64url_encode(claims.to_string().as_bytes());
        let sig = crate::talos::core::secrets::test_hmac(key, format!("{h}.{p}").as_bytes());
        format!("{h}.{p}.{}", base64url_encode(&sig))
    }

    fn validate(token: &str, config: serde_json::Value) -> Result<String, String> {
        let mut cfg = json!({"SECRET_NAME": "auth/jwt_secret"});
        for (k, v) in config.as_object().unwrap() {
            cfg[k] = v.clone();
        }
        run(json!({"config": cfg, "token": token}).to_string())
    }

    fn wall_clock() -> i64 {
        now_secs().unwrap()
    }

    #[test]
    fn end_to_end_a_signed_live_token_is_valid_and_an_expired_one_is_not() {
        let key = crate::talos::core::secrets::TEST_KEY;
        let hs256 = json!({"alg": "HS256", "typ": "JWT"});
        let live = token(hs256.clone(), json!({"sub": "u1", "exp": wall_clock() + 3600}), key);
        let out: serde_json::Value = serde_json::from_str(&validate(&live, json!({})).unwrap()).unwrap();
        assert_eq!(out["valid"], json!(true));
        assert_eq!(out["claims"]["sub"], json!("u1"));

        let expired = token(hs256.clone(), json!({"sub": "u1", "exp": wall_clock() - 3600}), key);
        assert_eq!(validate(&expired, json!({})), Err("JWT has expired".to_string()));

        let forever = token(hs256.clone(), json!({"sub": "u1"}), key);
        assert!(validate(&forever, json!({})).is_err());
        assert!(validate(&forever, json!({"ALLOW_NO_EXPIRY": true})).is_ok());
    }

    #[test]
    fn end_to_end_a_forged_token_fails_on_its_signature_before_anything_else() {
        let hs256 = json!({"alg": "HS256"});
        // Signed with the wrong key, and expired: the answer is about the
        // signature, so an unsigned token learns nothing about claim checks.
        let forged = token(hs256, json!({"exp": 1}), b"not-the-key");
        assert_eq!(
            validate(&forged, json!({})),
            Err("JWT signature verification failed".to_string())
        );
        // alg "none" with an empty signature.
        let h = base64url_encode(json!({"alg": "none"}).to_string().as_bytes());
        let p = base64url_encode(json!({"exp": wall_clock() + 3600}).to_string().as_bytes());
        assert_eq!(
            validate(&format!("{h}.{p}."), json!({})),
            Err("JWT signature verification failed".to_string())
        );
    }

    #[test]
    fn end_to_end_a_node_asking_for_another_algorithm_is_told() {
        let key = crate::talos::core::secrets::TEST_KEY;
        let t = token(json!({"alg": "HS256"}), json!({"exp": wall_clock() + 3600}), key);
        assert!(validate(&t, json!({"ALGORITHM": "HS256"})).is_ok());
        assert_eq!(
            validate(&t, json!({"ALGORITHM": "RS256"})),
            Err("ALGORITHM: only HS256 is supported".to_string())
        );
    }

    #[test]
    fn end_to_end_a_correctly_signed_token_naming_another_algorithm_is_refused() {
        let key = crate::talos::core::secrets::TEST_KEY;
        let t = token(json!({"alg": "HS512"}), json!({"exp": wall_clock() + 3600}), key);
        assert!(validate(&t, json!({})).unwrap_err().contains("not supported"));
    }
}
