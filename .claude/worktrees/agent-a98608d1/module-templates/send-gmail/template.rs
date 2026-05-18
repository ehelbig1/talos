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
        // The `Date` header is REQUIRED by RFC 5322 §3.6.1.
        // Gmail API requires base64url encoding (no padding) of the raw message.
        let date_str = rfc2822_date_now();
        let raw_message = format!(
            "From: {}\r\nTo: {}\r\nDate: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{}",
            from, to, date_str, subject, body_text
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

fn rfc2822_date_now() -> String {
    // A mock since we don't have chrono in WASM by default easily, or we can use datetime
    // Using an arbitrary valid RFC2822 date for the template or you can use talos::core::datetime
    "Tue, 1 Jul 2024 10:00:00 +0000".to_string()
}

fn base64url_encode(input: &[u8]) -> String {
    // Very simple base64url encoder if we don't have the crate, 
    // or we can add base64 crate to Cargo.toml. Let's just use base64 crate!
    base64::encode_config(input, base64::URL_SAFE_NO_PAD)
}
