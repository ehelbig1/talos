use talos_sdk_macros::talos_module;

#[talos_module(world = "minimal-node")]
fn run(input: String) -> Result<String, String> {
    let input_json: serde_json::Value =
        serde_json::from_str(&input).map_err(|e| format!("Invalid JSON input: {}", e))?;
    let config = input_json
        .get("config")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    // ── Extract config ───────────────────────────────────────────────────
    let patterns_str = config
        .get("PATTERNS_TO_REDACT")
        .and_then(|v| v.as_str())
        .unwrap_or("email,phone,ssn,credit_card,ip_address");

    let enabled_patterns: Vec<String> = if patterns_str.trim().eq_ignore_ascii_case("all") {
        vec![
            "email".to_string(),
            "phone".to_string(),
            "ssn".to_string(),
            "credit_card".to_string(),
            "ip_address".to_string(),
        ]
    } else {
        patterns_str
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    };

    let replacement_token = config
        .get("REPLACEMENT_TOKEN")
        .and_then(|v| v.as_str())
        .unwrap_or("[REDACTED]")
        .to_string();

    let use_typed_tokens = replacement_token.eq_ignore_ascii_case("typed");

    let input_field = config
        .get("INPUT_FIELD")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let preserve_format = config
        .get("PRESERVE_FORMAT")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // ── PII pattern matchers ─────────────────────────────────────────────
    // Each matcher scans a string and returns the scrubbed version + count.
    // Using character-level scanning (no regex crate dependency in WASM).

    struct Detection {
        pattern: String,
        count: usize,
    }

    let mut detections: Vec<Detection> = Vec::new();

    // Email: scan for pattern like word@word.word
    fn scrub_emails(text: &str, token: &str, preserve: bool) -> (String, usize) {
        let _ = preserve; // Emails don't have a meaningful partial format
        let chars: Vec<char> = text.chars().collect();
        let mut result = String::with_capacity(text.len());
        let mut count = 0;
        let mut i = 0;

        while i < chars.len() {
            // Look for @ sign and validate surrounding characters
            if chars[i] == '@' && i > 0 {
                // Walk backward to find start of local part
                let mut local_start = i;
                while local_start > 0 {
                    let c = chars[local_start - 1];
                    if c.is_alphanumeric() || c == '.' || c == '_' || c == '-' || c == '+' {
                        local_start -= 1;
                    } else {
                        break;
                    }
                }

                // Walk forward past @ to find domain
                let mut domain_end = i + 1;
                let mut has_dot = false;
                while domain_end < chars.len() {
                    let c = chars[domain_end];
                    if c.is_alphanumeric() || c == '.' || c == '-' {
                        if c == '.' {
                            has_dot = true;
                        }
                        domain_end += 1;
                    } else {
                        break;
                    }
                }

                // Validate: must have local part, domain part with dot
                if local_start < i && domain_end > i + 1 && has_dot {
                    // Remove already-appended local part chars from result
                    let chars_to_remove = i - local_start;
                    for _ in 0..chars_to_remove {
                        result.pop();
                    }
                    result.push_str(token);
                    count += 1;
                    i = domain_end;
                    continue;
                }
            }
            result.push(chars[i]);
            i += 1;
        }
        (result, count)
    }

    // Phone: scan for patterns like (xxx) xxx-xxxx, xxx-xxx-xxxx, +1xxxxxxxxxx
    fn scrub_phones(text: &str, token: &str, _preserve: bool) -> (String, usize) {
        let chars: Vec<char> = text.chars().collect();
        let mut result = String::with_capacity(text.len());
        let mut count = 0;
        let mut i = 0;

        while i < chars.len() {
            // Check for phone-like sequences: 10+ digits with optional separators
            if chars[i] == '+' || chars[i] == '(' || chars[i].is_ascii_digit() {
                let start = i;
                let mut digit_count = 0;
                let mut j = i;

                while j < chars.len() {
                    let c = chars[j];
                    if c.is_ascii_digit() {
                        digit_count += 1;
                        j += 1;
                    } else if c == '-' || c == '.' || c == ' ' || c == '(' || c == ')' || c == '+' {
                        j += 1;
                    } else {
                        break;
                    }
                }

                // Phone numbers have 10-15 digits
                if digit_count >= 10 && digit_count <= 15 {
                    result.push_str(token);
                    count += 1;
                    i = j;
                    continue;
                }
            }
            result.push(chars[i]);
            i += 1;
        }
        (result, count)
    }

    // SSN: scan for pattern xxx-xx-xxxx or xxxxxxxxx (9 digits)
    fn scrub_ssns(text: &str, token: &str, preserve: bool) -> (String, usize) {
        let chars: Vec<char> = text.chars().collect();
        let mut result = String::with_capacity(text.len());
        let mut count = 0;
        let mut i = 0;

        while i < chars.len() {
            // Check for xxx-xx-xxxx pattern
            if i + 10 < chars.len()
                && chars[i].is_ascii_digit()
                && chars[i + 1].is_ascii_digit()
                && chars[i + 2].is_ascii_digit()
                && chars[i + 3] == '-'
                && chars[i + 4].is_ascii_digit()
                && chars[i + 5].is_ascii_digit()
                && chars[i + 6] == '-'
                && chars[i + 7].is_ascii_digit()
                && chars[i + 8].is_ascii_digit()
                && chars[i + 9].is_ascii_digit()
                && chars[i + 10].is_ascii_digit()
            {
                // Verify not preceded or followed by digit (avoid matching within larger numbers)
                let preceded_by_digit = i > 0 && chars[i - 1].is_ascii_digit();
                let followed_by_digit =
                    i + 11 < chars.len() && chars[i + 11].is_ascii_digit();

                if !preceded_by_digit && !followed_by_digit {
                    if preserve {
                        result.push_str(&format!(
                            "***-**-{}",
                            &text[i + 7..i + 11]
                        ));
                    } else {
                        result.push_str(token);
                    }
                    count += 1;
                    i += 11;
                    continue;
                }
            }
            result.push(chars[i]);
            i += 1;
        }
        (result, count)
    }

    // Credit card: scan for 4 groups of 4 digits separated by spaces or dashes
    fn scrub_credit_cards(text: &str, token: &str, preserve: bool) -> (String, usize) {
        let chars: Vec<char> = text.chars().collect();
        let mut result = String::with_capacity(text.len());
        let mut count = 0;
        let mut i = 0;

        while i < chars.len() {
            if chars[i].is_ascii_digit() {
                // Try to match xxxx-xxxx-xxxx-xxxx or xxxx xxxx xxxx xxxx
                let start = i;
                let mut digits = Vec::new();
                let mut j = i;

                while j < chars.len() && digits.len() < 20 {
                    let c = chars[j];
                    if c.is_ascii_digit() {
                        digits.push(c);
                        j += 1;
                    } else if (c == '-' || c == ' ') && !digits.is_empty() {
                        j += 1;
                    } else {
                        break;
                    }
                }

                // Credit cards have 13-19 digits, most commonly 16
                if digits.len() >= 13 && digits.len() <= 19 {
                    // Luhn check for validation
                    let luhn_valid = {
                        let mut sum = 0u32;
                        let mut double = false;
                        for d in digits.iter().rev() {
                            let mut n = (*d as u32) - ('0' as u32);
                            if double {
                                n *= 2;
                                if n > 9 {
                                    n -= 9;
                                }
                            }
                            sum += n;
                            double = !double;
                        }
                        sum % 10 == 0
                    };

                    if luhn_valid {
                        // Verify not preceded by digit
                        let preceded = start > 0 && chars[start - 1].is_ascii_digit();
                        let followed = j < chars.len() && chars[j].is_ascii_digit();

                        if !preceded && !followed {
                            if preserve {
                                let last4: String = digits[digits.len() - 4..].iter().collect();
                                result.push_str(&format!("****-****-****-{}", last4));
                            } else {
                                result.push_str(token);
                            }
                            count += 1;
                            i = j;
                            continue;
                        }
                    }
                }
            }
            result.push(chars[i]);
            i += 1;
        }
        (result, count)
    }

    // IP address: scan for x.x.x.x where each octet is 0-255
    fn scrub_ip_addresses(text: &str, token: &str, _preserve: bool) -> (String, usize) {
        let chars: Vec<char> = text.chars().collect();
        let mut result = String::with_capacity(text.len());
        let mut count = 0;
        let mut i = 0;

        while i < chars.len() {
            if chars[i].is_ascii_digit() {
                // Try to parse an IP address starting here
                let start = i;

                // Don't match if preceded by digit or dot
                if start > 0 && (chars[start - 1].is_ascii_digit() || chars[start - 1] == '.') {
                    result.push(chars[i]);
                    i += 1;
                    continue;
                }

                let mut octets = Vec::new();
                let mut j = i;

                for octet_idx in 0..4 {
                    let mut num_str = String::new();
                    while j < chars.len() && chars[j].is_ascii_digit() && num_str.len() < 3 {
                        num_str.push(chars[j]);
                        j += 1;
                    }

                    if num_str.is_empty() {
                        break;
                    }

                    if let Ok(n) = num_str.parse::<u32>() {
                        if n <= 255 {
                            octets.push(n);
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }

                    // Expect a dot between octets (but not after the last one)
                    if octet_idx < 3 {
                        if j < chars.len() && chars[j] == '.' {
                            j += 1;
                        } else {
                            break;
                        }
                    }
                }

                if octets.len() == 4 {
                    // Don't match if followed by digit or dot
                    let followed = j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == '.');
                    if !followed {
                        result.push_str(token);
                        count += 1;
                        i = j;
                        continue;
                    }
                }
            }
            result.push(chars[i]);
            i += 1;
        }
        (result, count)
    }

    // ── Apply scrubbing to a string value ────────────────────────────────
    fn scrub_string(
        text: &str,
        patterns: &[String],
        replacement: &str,
        use_typed: bool,
        preserve: bool,
        detections: &mut Vec<Detection>,
    ) -> String {
        let mut current = text.to_string();

        for pattern in patterns {
            let token = if use_typed {
                format!("[REDACTED_{}]", pattern.to_uppercase())
            } else {
                replacement.to_string()
            };

            let (scrubbed, found_count) = match pattern.as_str() {
                "email" => scrub_emails(&current, &token, preserve),
                "phone" => scrub_phones(&current, &token, preserve),
                "ssn" => scrub_ssns(&current, &token, preserve),
                "credit_card" => scrub_credit_cards(&current, &token, preserve),
                "ip_address" => scrub_ip_addresses(&current, &token, preserve),
                _ => (current.clone(), 0),
            };

            if found_count > 0 {
                // Accumulate into existing detection for this pattern
                let existing = detections.iter_mut().find(|d| d.pattern == *pattern);
                if let Some(det) = existing {
                    det.count += found_count;
                } else {
                    detections.push(Detection {
                        pattern: pattern.clone(),
                        count: found_count,
                    });
                }
            }

            current = scrubbed;
        }

        current
    }

    // ── Recursive JSON scrubbing ─────────────────────────────────────────
    fn scrub_value(
        value: &serde_json::Value,
        patterns: &[String],
        replacement: &str,
        use_typed: bool,
        preserve: bool,
        detections: &mut Vec<Detection>,
    ) -> serde_json::Value {
        match value {
            serde_json::Value::String(s) => {
                let scrubbed = scrub_string(s, patterns, replacement, use_typed, preserve, detections);
                serde_json::Value::String(scrubbed)
            }
            serde_json::Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (k, v) in map {
                    new_map.insert(
                        k.clone(),
                        scrub_value(v, patterns, replacement, use_typed, preserve, detections),
                    );
                }
                serde_json::Value::Object(new_map)
            }
            serde_json::Value::Array(arr) => {
                let new_arr: Vec<serde_json::Value> = arr
                    .iter()
                    .map(|v| scrub_value(v, patterns, replacement, use_typed, preserve, detections))
                    .collect();
                serde_json::Value::Array(new_arr)
            }
            // Numbers, booleans, and null pass through unchanged
            other => other.clone(),
        }
    }

    // ── Apply scrubbing ──────────────────────────────────────────────────
    let data = input_json
        .get("input")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let scrubbed = if let Some(ref field) = input_field {
        // Scrub only a specific field
        match data.clone() {
            serde_json::Value::Object(mut map) => {
                if let Some(field_val) = map.get(field).cloned() {
                    let scrubbed_field = scrub_value(
                        &field_val,
                        &enabled_patterns,
                        &replacement_token,
                        use_typed_tokens,
                        preserve_format,
                        &mut detections,
                    );
                    map.insert(field.clone(), scrubbed_field);
                }
                serde_json::Value::Object(map)
            }
            other => scrub_value(
                &other,
                &enabled_patterns,
                &replacement_token,
                use_typed_tokens,
                preserve_format,
                &mut detections,
            ),
        }
    } else {
        // Scrub all string values recursively
        scrub_value(
            &data,
            &enabled_patterns,
            &replacement_token,
            use_typed_tokens,
            preserve_format,
            &mut detections,
        )
    };

    let total_redactions: usize = detections.iter().map(|d| d.count).sum();

    let detection_summary: Vec<serde_json::Value> = detections
        .iter()
        .map(|d| {
            serde_json::json!({
                "pattern": d.pattern,
                "count": d.count,
            })
        })
        .collect();

    let result = serde_json::json!({
        "scrubbed": scrubbed,
        "detections": detection_summary,
        "total_redactions": total_redactions,
        "patterns_checked": enabled_patterns,
    });

    serde_json::to_string(&result).map_err(|e| format!("Failed to serialize output: {}", e))
}
