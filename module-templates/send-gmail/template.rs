use talos_sdk_macros::talos_module;
use serde_json::Value;

#[talos_module(world = "network-node")]
fn run(input: String) -> Result<String, String> {
        use talos::core::logging::{self, Level};
        use talos::core::http::{Method, Request};

        let input_json: Value = serde_json::from_str(&input)
            .map_err(|e| format!("Invalid JSON input: {}", e))?;

        let config = input_json.get("config")
            .ok_or("Missing config")?;

        // ACCESS_TOKEN is resolved from secrets by the controller before WASM execution.
        // SECURITY: never log the token value.
        let access_token = config.get("ACCESS_TOKEN")
            .and_then(|v| v.as_str())
            .ok_or("Missing ACCESS_TOKEN in config (set a secret reference)")?;

        let to = config.get("TO")
            .and_then(|v| v.as_str())
            .ok_or("Missing TO in config")?;

        let subject = config.get("SUBJECT")
            .and_then(|v| v.as_str())
            .ok_or("Missing SUBJECT in config")?;

        let body_text = config.get("BODY")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let from = config.get("FROM")
            .and_then(|v| v.as_str())
            .unwrap_or("me");

        // SECURITY: validate header fields against email header injection (CWE-93).
        // An attacker who controls `to`, `from`, or `subject` could inject arbitrary
        // headers by embedding CR (\r) or LF (\n) characters into the field value,
        // splitting the header and adding new headers (e.g. BCC, Content-Type overrides).
        reject_crlf(from, "FROM")?;
        reject_crlf(to, "TO")?;
        reject_crlf(subject, "SUBJECT")?;

        logging::log(Level::Info, &format!("Sending Gmail to: {}", to));

        // Construct an RFC 2822 message.
        // - The Subject is RFC 2047-encoded when it carries non-ASCII, so an
        //   un-encoded UTF-8 header can't mojibake in the recipient's client.
        // - No Date header is emitted: the Gmail API populates a correct one on
        //   send. (This template previously hardcoded a fixed 2024 date, which
        //   stamped every message with the wrong date.)
        // Gmail API requires base64url encoding (no padding) of the raw message.
        let subject_header = encode_subject(subject);
        let raw_message = format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{}",
            from, to, subject_header, body_text
        );

        let encoded = base64url_encode(raw_message.as_bytes());

        let send_payload = serde_json::json!({ "raw": encoded });
        let send_body = serde_json::to_vec(&send_payload)
            .map_err(|e| format!("Failed to serialize send payload: {}", e))?;

        let req = Request {
            method: Method::Post,
            url: "https://gmail.googleapis.com/gmail/v1/users/me/messages/send".to_string(),
            headers: vec![
                ("Authorization".to_string(), format!("Bearer {}", access_token)),
                ("Content-Type".to_string(), "application/json".to_string()),
            ],
            body: send_body,
            timeout_ms: Some(15_000),
        };

        let resp = talos::core::http::fetch(&req)
            .map_err(|e| format!("HTTP request failed: {:?}", e))?;

        logging::log(Level::Info, &format!("Gmail API returned HTTP {}", resp.status));

        if resp.status != 200 {
            return Err(format!("Gmail API returned HTTP {}", resp.status));
        }

        let body_str = String::from_utf8(resp.body)
            .map_err(|_| "Invalid UTF-8 in Gmail API response".to_string())?;
        let sent: Value = serde_json::from_str(&body_str)
            .map_err(|e| format!("Failed to parse Gmail API response: {}", e))?;

        let output = serde_json::json!({
            "success": true,
            "message_id": sent.get("id").cloned().unwrap_or(serde_json::json!(null)),
            "thread_id": sent.get("threadId").cloned().unwrap_or(serde_json::json!(null)),
            "label_ids": sent.get("labelIds").cloned().unwrap_or(serde_json::json!([])),
            "to": to,
            "subject": subject,
        });

        serde_json::to_string(&output)
            .map_err(|e| format!("Failed to serialize output: {}", e))
    }

fn reject_crlf(val: &str, field: &str) -> Result<(), String> {
    if val.contains('\n') || val.contains('\r') {
        Err(format!("CRLF injection detected in {}", field))
    } else {
        Ok(())
    }
}

// RFC 2047 "encoded-word" for the Subject header. ASCII subjects pass through
// unchanged (byte-identical to the old behavior). Non-ASCII subjects become
// =?UTF-8?B?..?= words, each <= 75 chars and never splitting a multi-byte
// character, folded with CRLF+space (the whitespace between words is elided by
// the reader).
fn encode_subject(subject: &str) -> String {
    if subject.is_ascii() {
        return subject.to_string();
    }
    let mut words: Vec<String> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    for ch in subject.chars() {
        let mut tmp = [0u8; 4];
        let bytes = ch.encode_utf8(&mut tmp).as_bytes();
        // Keep each word's payload <= 45 bytes => <= 60 base64 chars, comfortably
        // under the 75-char encoded-word limit incl. the 12-char envelope.
        if buf.len() + bytes.len() > 45 && !buf.is_empty() {
            words.push(format!("=?UTF-8?B?{}?=", base64_standard(&buf)));
            buf.clear();
        }
        buf.extend_from_slice(bytes);
    }
    if !buf.is_empty() {
        words.push(format!("=?UTF-8?B?{}?=", base64_standard(&buf)));
    }
    words.join("\r\n ")
}

// Standard base64 (RFC 4648, WITH padding) — required by RFC 2047 encoded-words.
fn base64_standard(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64url_encode(input: &[u8]) -> String {
    // Pure-Rust base64url encoder (URL-safe alphabet, no padding).
    // Avoids the `base64` crate which is not available in the WASM sandbox.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < input.len() { input[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] as u32 } else { 0 };
        out.push(ALPHABET[((b0 >> 2) & 0x3F) as usize] as char);
        out.push(ALPHABET[(((b0 << 4) | (b1 >> 4)) & 0x3F) as usize] as char);
        if i + 1 < input.len() { out.push(ALPHABET[(((b1 << 2) | (b2 >> 6)) & 0x3F) as usize] as char); }
        if i + 2 < input.len() { out.push(ALPHABET[(b2 & 0x3F) as usize] as char); }
        i += 3;
    }
    out
}
