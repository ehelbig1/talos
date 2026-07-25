use talos_sdk_macros::talos_module;
use serde_json::Value;

// send-html-email — the input-driven HTML email sender for the two-node
// compose -> send delivery pattern (docs/delivery-node-pattern.md).
//
// Reads {html, subject} from the UPSTREAM node's output (a compose node with
// memory + no network), resolves a `vault://` bearer token carried in the
// AUTH_HEADER config (the host substitutes it into the outbound header and
// zeroizes the plaintext), RFC 2047-encodes non-ASCII subjects, and POSTs an
// HTML message to the Gmail API. DRY_RUN gates the actual send.
//
// Keep `capability_world` in talos.json in sync with the macro world below
// (lint check 48). No Date header is emitted — the Gmail API populates one on
// send, which is always correct; a module-computed date is a needless failure
// mode (the older send-gmail template hardcoded a 2024 date).
#[talos_module(world = "http-node")]
fn run(input: String) -> Result<String, String> {
    use talos::core::http::{Method, Request};
    use talos::core::logging::{self, Level};

    let root: Value = serde_json::from_str(&input)
        .map_err(|e| format!("Invalid JSON input: {}", e))?;

    let config = root.get("config").cloned().unwrap_or(Value::Null);

    // Auth + recipient come from node config.
    let auth_header = str_field(&config, "AUTH_HEADER")
        .ok_or("Missing AUTH_HEADER in config (a Bearer value, e.g. a vault:// token reference)")?;
    let to = str_field(&config, "TO").ok_or("Missing TO in config")?;
    let from = str_field(&config, "FROM").unwrap_or_else(|| "me".to_string());
    let dry_run = config.get("DRY_RUN").and_then(|v| v.as_bool()).unwrap_or(false);

    // Content comes from the upstream node's output ({subject, html}); a config
    // fallback lets the module run stand-alone in a sandbox test.
    let subject = pick(&root, "subject").unwrap_or_else(|| "(no subject)".to_string());
    let html = pick(&root, "html").unwrap_or_default();

    // CWE-93: reject CRLF in header-bound fields (raw subject, TO, FROM) so a
    // caller can't split the header block and inject BCC / Content-Type.
    reject_crlf(&to, "TO")?;
    reject_crlf(&from, "FROM")?;
    reject_crlf(&subject, "SUBJECT")?;

    // RFC 2047-encode the subject when it carries non-ASCII, so the header can't
    // mojibake. ASCII subjects pass through byte-identical.
    let subject_header = encode_subject(&subject);

    let raw_message = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n{}",
        from, to, subject_header, html
    );

    if dry_run {
        let out = serde_json::json!({
            "sent": false,
            "dry_run": true,
            "to": to,
            "subject": subject,
            "rfc822_bytes": raw_message.len(),
        });
        return serde_json::to_string(&out).map_err(|e| format!("serialize error: {}", e));
    }

    let encoded = base64url_encode(raw_message.as_bytes());
    let send_payload = serde_json::json!({ "raw": encoded });
    let send_body =
        serde_json::to_vec(&send_payload).map_err(|e| format!("serialize send payload: {}", e))?;

    logging::log(Level::Info, &format!("Sending HTML email to: {}", to));

    let req = Request {
        method: Method::Post,
        url: "https://gmail.googleapis.com/gmail/v1/users/me/messages/send".to_string(),
        headers: vec![
            // AUTH_HEADER may carry a vault:// reference; the host resolves it
            // into the outbound header and zeroizes the plaintext after use.
            ("Authorization".to_string(), auth_header),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: send_body,
        timeout_ms: Some(15_000),
    };

    let resp =
        talos::core::http::fetch(&req).map_err(|e| format!("HTTP request failed: {:?}", e))?;

    if resp.status != 200 {
        // Do NOT echo the response body — it can contain request context.
        return Err(format!("Gmail API returned HTTP {}", resp.status));
    }

    let body_str =
        String::from_utf8(resp.body).map_err(|_| "Invalid UTF-8 in Gmail API response".to_string())?;
    let sent: Value =
        serde_json::from_str(&body_str).map_err(|e| format!("parse Gmail API response: {}", e))?;

    let out = serde_json::json!({
        "sent": true,
        "dry_run": false,
        "message_id": sent.get("id").cloned().unwrap_or(Value::Null),
        "thread_id": sent.get("threadId").cloned().unwrap_or(Value::Null),
        "to": to,
        "subject": subject,
    });
    serde_json::to_string(&out).map_err(|e| format!("serialize error: {}", e))
}

// Read a string field from a JSON object.
fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
}

// Pick `key` from the upstream output first (root["input"]), then node config,
// then the root — robust to how the engine nests the compose node's output.
fn pick(root: &Value, key: &str) -> Option<String> {
    root.get("input")
        .and_then(|i| i.get(key))
        .and_then(|v| v.as_str())
        .or_else(|| {
            root.get("config")
                .and_then(|c| c.get(key))
                .and_then(|v| v.as_str())
        })
        .or_else(|| root.get(key).and_then(|v| v.as_str()))
        .map(|s| s.to_string())
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
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(A[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(A[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

// base64url (no padding) for the Gmail messages.send `raw` field.
fn base64url_encode(input: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(A[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(A[(n & 63) as usize] as char);
        }
    }
    out
}
