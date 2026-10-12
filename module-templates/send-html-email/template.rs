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
// Two things it does NOT send (2026-10-12; until then it sent both):
//   * `skip: true` from the compose node. That is how a composer says "there
//     is nothing to send this time"; the answer is {sent:false, skipped:true}.
//   * a message with no `html`. With neither `subject` nor `html` in its
//     input it used to send "(no subject)" with an empty body. An empty body
//     is now an error naming what was missing, so the node fails where it can
//     be seen instead of mailing a blank.
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

    // The composer said there is nothing to send. Checked before the content,
    // because a composer that skips usually returns no content at all.
    if upstream_skips(&root) {
        let out = serde_json::json!({
            "sent": false,
            "skipped": true,
            "dry_run": dry_run,
            "to": to,
        });
        return serde_json::to_string(&out).map_err(|e| format!("serialize error: {}", e));
    }

    // Content comes from the upstream node's output ({subject, html}); a config
    // fallback lets the module run stand-alone in a sandbox test.
    let subject = pick(&root, "subject").unwrap_or_else(|| "(no subject)".to_string());
    let html = pick(&root, "html").unwrap_or_default();

    // Never a blank email. Checked ahead of DRY_RUN too, so a rehearsal fails
    // the same way the real send would.
    if html.trim().is_empty() {
        return Err(
            "Nothing to send: the input has no `html` (or it is empty). The upstream node must \
             return {subject, html}, or {skip: true} when there is nothing to send this time."
                .to_string(),
        );
    }

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

// `skip: true` in the upstream node's output (root["input"]) or, for a
// stand-alone run, at the root. Only the boolean `true` skips: a string
// "true" or a 1 is not the composer's contract and is not read as one.
fn upstream_skips(root: &Value) -> bool {
    let flag = |v: &Value| v.get("skip").and_then(|s| s.as_bool()) == Some(true);
    root.get("input").map(flag).unwrap_or(false) || flag(root)
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use talos_module_testkit::host;

    fn config() -> Value {
        json!({ "AUTH_HEADER": "Bearer vault://oauth/gmail/made-up/access_token", "TO": "reader@example.com" })
    }

    fn send(config: Value, input: Value) -> Result<Value, String> {
        let out = run(json!({ "config": config, "input": input }).to_string())?;
        Ok(serde_json::from_str(&out).expect("the module returns JSON"))
    }

    // The RFC 822 text the module asked Gmail to send.
    fn sent_message() -> String {
        let requests = host::http::requests();
        assert_eq!(requests.len(), 1, "one send expected");
        let body: Value = serde_json::from_slice(&requests[0].body).expect("a JSON body");
        let raw = body["raw"].as_str().expect("a raw field");
        String::from_utf8(base64url_decode(raw)).expect("utf-8")
    }

    fn base64url_decode(text: &str) -> Vec<u8> {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = Vec::new();
        let (mut acc, mut bits) = (0u32, 0u32);
        for byte in text.bytes() {
            let value = A.iter().position(|a| *a == byte).expect("base64url") as u32;
            acc = (acc << 6) | value;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        out
    }

    #[test]
    fn a_composed_message_is_sent_once_with_its_subject_and_body() {
        host::http::respond(200, r#"{"id":"made-up-message","threadId":"made-up-thread"}"#);
        let v = send(config(), json!({ "subject": "Your morning", "html": "<p>Three things.</p>" })).unwrap();
        assert_eq!(v["sent"], json!(true));
        assert_eq!(v["message_id"], json!("made-up-message"));
        assert_eq!(v["thread_id"], json!("made-up-thread"));

        let request = &host::http::requests()[0];
        assert_eq!(request.url, "https://gmail.googleapis.com/gmail/v1/users/me/messages/send");
        let message = sent_message();
        assert!(message.contains("To: reader@example.com\r\n"), "{message}");
        assert!(message.contains("Subject: Your morning\r\n"), "{message}");
        assert!(message.ends_with("\r\n\r\n<p>Three things.</p>"), "{message}");
    }

    /// The observed case: with neither `subject` nor `html` in its input the
    /// module sent "(no subject)" with an empty body.
    #[test]
    fn a_message_with_no_body_is_refused_and_nothing_is_sent() {
        host::http::respond(200, r#"{"id":"x"}"#);
        for input in [
            json!({}),
            json!({ "subject": "Your morning" }),
            json!({ "subject": "Your morning", "html": "" }),
            json!({ "subject": "Your morning", "html": "  \n\t " }),
            json!({ "html": 7 }),
        ] {
            let said = send(config(), input.clone()).unwrap_err();
            assert!(said.starts_with("Nothing to send: the input has no `html`"), "{input}: {said}");
        }
        assert!(host::http::requests().is_empty(), "a blank message reached Gmail");

        // A rehearsal fails the same way the real send would.
        let mut dry = config();
        dry["DRY_RUN"] = json!(true);
        assert!(send(dry, json!({ "subject": "s" })).unwrap_err().starts_with("Nothing to send"));
    }

    /// `skip: true` is how the composer says "nothing this time". It was ignored.
    #[test]
    fn skip_sends_nothing_and_says_so() {
        host::http::respond(200, r#"{"id":"x"}"#);
        // A composer that skips usually returns no content at all.
        let v = send(config(), json!({ "skip": true })).unwrap();
        assert_eq!((v["sent"].clone(), v["skipped"].clone()), (json!(false), json!(true)));
        // And one that returns content beside it is still skipped.
        let v = send(config(), json!({ "skip": true, "subject": "s", "html": "<p>b</p>" })).unwrap();
        assert_eq!((v["sent"].clone(), v["skipped"].clone()), (json!(false), json!(true)));
        assert!(host::http::requests().is_empty(), "a skipped message reached Gmail");

        // Only the boolean true skips: anything else is sent, as before.
        for not_a_skip in [json!(false), json!("true"), json!(1), Value::Null] {
            let v = send(config(), json!({ "skip": not_a_skip, "subject": "s", "html": "<p>b</p>" })).unwrap();
            assert_eq!(v["sent"], json!(true));
            assert!(v.get("skipped").is_none());
        }
    }

    #[test]
    fn a_dry_run_builds_the_message_and_sends_nothing() {
        let mut dry = config();
        dry["DRY_RUN"] = json!(true);
        let v = send(dry, json!({ "subject": "s", "html": "<p>b</p>" })).unwrap();
        assert_eq!((v["sent"].clone(), v["dry_run"].clone()), (json!(false), json!(true)));
        assert!(v["rfc822_bytes"].as_u64().unwrap() > 0);
        assert!(host::http::requests().is_empty());
    }

    #[test]
    fn a_header_cannot_be_split_and_a_non_ascii_subject_is_encoded() {
        host::http::respond(200, r#"{"id":"x"}"#);
        let said = send(config(), json!({ "subject": "s\r\nBcc: other@example.com", "html": "<p>b</p>" })).unwrap_err();
        assert_eq!(said, "CRLF injection detected in SUBJECT");
        assert!(host::http::requests().is_empty());

        send(config(), json!({ "subject": "Café ☕", "html": "<p>b</p>" })).unwrap();
        let message = sent_message();
        assert!(message.contains("Subject: =?UTF-8?B?"), "{message}");
    }

    /// The platform retries a timeout or a network error, and the message is
    /// all it has to go on.
    #[test]
    fn a_failed_send_names_how_it_failed_and_never_echoes_the_reply() {
        use talos::core::http::Error;
        host::http::respond_with(|_| Err(Error::Networkerror));
        let said = send(config(), json!({ "subject": "s", "html": "<p>b</p>" })).unwrap_err();
        assert!(said.to_lowercase().contains("networkerror"), "{said}");

        host::http::respond(500, "made-up upstream detail");
        let said = send(config(), json!({ "subject": "s", "html": "<p>b</p>" })).unwrap_err();
        assert_eq!(said, "Gmail API returned HTTP 500");
    }
}
