use serde::Deserialize;
use serde_json::Value;
use talos_sdk_macros::talos_module;

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
// It returns the delivery verdict every sender of a message returns
// (docs/building-blocks.md, "Sender"; 2026-10-16): `provider`, `sent`,
// `skipped`, `dry_run`, `parts_total`, `parts_sent`, `actions_sent`, beside
// the Gmail ids. The engine reads those fields at node completion and records
// the send (`message_deliveries`), so the Sunday email is counted beside the
// phone notifications and a tap on one of its buttons is set against it. One
// email is one part; `actions_sent` is the number of action links in the body.
//
// Keep `capability_world` in talos.json in sync with the macro world below
// (lint check 48). No Date header is emitted — the Gmail API populates one on
// send, which is always correct; a module-computed date is a needless failure
// mode (the older send-gmail template hardcoded a 2024 date).
#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    use talos::core::http::{Method, Request};
    use talos::core::logging::{self, Level};

    // Typed, not `serde_json::Value`: the input carries the whole composed
    // message, and a `Value` tree of it cost about 200 fuel per byte of body
    // (measured 2026-10-12: a 30 KB message used 6.2M fuel and could not be
    // sent under the default limit). The fields this module does not read are
    // skipped by the parser, never built.
    let root: Root =
        serde_json::from_str(&input).map_err(|e| format!("Invalid JSON input: {}", e))?;
    let Root {
        config,
        input: upstream,
        subject: root_subject,
        html: root_html,
        skip: root_skip,
    } = root;
    let upstream = upstream.unwrap_or_default();

    // Auth + recipient come from node config.
    let auth_header = config
        .auth_header
        .0
        .ok_or("Missing AUTH_HEADER in config (a Bearer value, e.g. a vault:// token reference)")?;
    let to = config.to.0.ok_or("Missing TO in config")?;
    let from = config.from.0.unwrap_or_else(|| "me".to_string());
    let dry_run = config.dry_run == Some(Value::Bool(true));

    // The composer said there is nothing to send. Checked before the content,
    // because a composer that skips usually returns no content at all. Only
    // the boolean `true` skips: a string "true" or a 1 is not the composer's
    // contract and is not read as one.
    let skips = |flag: &Option<Value>| *flag == Some(Value::Bool(true));
    if skips(&upstream.skip) || skips(&root_skip) {
        let out = serde_json::json!({
            "provider": PROVIDER,
            "sent": false,
            "skipped": true,
            "dry_run": dry_run,
            "parts_total": 0,
            "parts_sent": 0,
            "actions_sent": 0,
            "to": to,
        });
        return serde_json::to_string(&out).map_err(|e| format!("serialize error: {}", e));
    }

    // Content comes from the upstream node's output first (`input`), then
    // node config (a stand-alone sandbox run), then the root — robust to how
    // the engine nests the compose node's output.
    let subject = upstream
        .subject
        .0
        .or(config.subject.0)
        .or(root_subject.0)
        .unwrap_or_else(|| "(no subject)".to_string());
    let html = upstream
        .html
        .0
        .or(config.html.0)
        .or(root_html.0)
        .unwrap_or_default();

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

    // What the message carries that a reader can act on: counted before the
    // send so a dry run reports it too.
    let actions_sent = count_action_links(&html);

    // The message, built once. The body is copied here and nowhere else.
    let mut raw_message: Vec<u8> = Vec::with_capacity(html.len() + 256);
    for part in [
        "From: ",
        from.as_str(),
        "\r\nTo: ",
        to.as_str(),
        "\r\nSubject: ",
        subject_header.as_str(),
        "\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n",
        html.as_str(),
    ] {
        raw_message.extend_from_slice(part.as_bytes());
    }

    if dry_run {
        let out = serde_json::json!({
            "provider": PROVIDER,
            "sent": false,
            "skipped": false,
            "dry_run": true,
            "parts_total": 1,
            "parts_sent": 0,
            "actions_sent": actions_sent,
            "to": to,
            "subject": subject,
            "rfc822_bytes": raw_message.len(),
        });
        return serde_json::to_string(&out).map_err(|e| format!("serialize error: {}", e));
    }

    // `{"raw":"<base64url>"}`, written straight into the request body. The
    // base64url alphabet has no character JSON escapes, so this is the same
    // bytes `serde_json` would produce without a second pass over them.
    let mut send_body: Vec<u8> = Vec::with_capacity(raw_message.len() / 3 * 4 + 16);
    send_body.extend_from_slice(b"{\"raw\":\"");
    base64url_encode_into(&raw_message, &mut send_body);
    send_body.extend_from_slice(b"\"}");

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
        "provider": PROVIDER,
        "sent": true,
        "skipped": false,
        "dry_run": false,
        "parts_total": 1,
        "parts_sent": 1,
        "actions_sent": actions_sent,
        "message_id": sent.get("id").cloned().unwrap_or(Value::Null),
        "thread_id": sent.get("threadId").cloned().unwrap_or(Value::Null),
        "to": to,
        "subject": subject,
    });
    serde_json::to_string(&out).map_err(|e| format!("serialize error: {}", e))
}

/// The delivery verdict's word for the service this adapter sends through.
const PROVIDER: &str = "gmail";

/// The path every minted action link carries (`docs/action-links.md`):
/// `<origin>/action-links/<token>`, written into the body by the
/// `action_links` node in place of the composer's `talos-action:<id>`.
const ACTION_LINK_PATH: &str = "/action-links/";

/// The most `actions_sent` reports; the delivery verdict's bound.
const MAX_ACTIONS_REPORTED: usize = 1024;

/// How many action links the body carries. A link the platform could not
/// mint fell back to `#` or a `mailto:` and is not one; a count past the
/// verdict's bound reports the bound, so a body that repeats the path a
/// thousand times cannot make the send unrecordable. One pass over the body,
/// no allocation.
fn count_action_links(html: &str) -> usize {
    html.matches(ACTION_LINK_PATH).count().min(MAX_ACTIONS_REPORTED)
}

// The whole input: `{config, input, …}`. `input` is the upstream node's
// output; `subject` / `html` / `skip` are also read at the root, where a
// stand-alone run or a flattened payload puts them.
#[derive(Deserialize, Default)]
struct Root {
    #[serde(default)]
    config: Config,
    #[serde(default)]
    input: Option<Content>,
    #[serde(default)]
    subject: Text,
    #[serde(default)]
    html: Text,
    #[serde(default)]
    skip: Option<Value>,
}

#[derive(Deserialize, Default)]
struct Config {
    #[serde(rename = "AUTH_HEADER", default)]
    auth_header: Text,
    #[serde(rename = "TO", default)]
    to: Text,
    #[serde(rename = "FROM", default)]
    from: Text,
    #[serde(rename = "DRY_RUN", default)]
    dry_run: Option<Value>,
    #[serde(default)]
    subject: Text,
    #[serde(default)]
    html: Text,
}

#[derive(Deserialize, Default)]
struct Content {
    #[serde(default)]
    subject: Text,
    #[serde(default)]
    html: Text,
    #[serde(default)]
    skip: Option<Value>,
}

// A field that is a string, or is treated as absent. A number, an object or a
// null where a string belongs is not this module's input and reads as "not
// given" (as `Value::as_str` did), never as a parse failure of the whole
// payload. Whatever it holds instead is skipped, not built.
#[derive(Default)]
struct Text(Option<String>);

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TextVisitor;
        impl<'de> serde::de::Visitor<'de> for TextVisitor {
            type Value = Text;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_str<E>(self, v: &str) -> Result<Text, E> {
                Ok(Text(Some(v.to_string())))
            }
            fn visit_string<E>(self, v: String) -> Result<Text, E> {
                Ok(Text(Some(v)))
            }
            fn visit_bool<E>(self, _: bool) -> Result<Text, E> {
                Ok(Text(None))
            }
            fn visit_i64<E>(self, _: i64) -> Result<Text, E> {
                Ok(Text(None))
            }
            fn visit_u64<E>(self, _: u64) -> Result<Text, E> {
                Ok(Text(None))
            }
            fn visit_f64<E>(self, _: f64) -> Result<Text, E> {
                Ok(Text(None))
            }
            fn visit_unit<E>(self) -> Result<Text, E> {
                Ok(Text(None))
            }
            fn visit_none<E>(self) -> Result<Text, E> {
                Ok(Text(None))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Text, A::Error> {
                while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(Text(None))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Text, A::Error> {
                while map
                    .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                    .is_some()
                {}
                Ok(Text(None))
            }
        }
        deserializer.deserialize_any(TextVisitor)
    }
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

// base64url (no padding) for the Gmail messages.send `raw` field, appended to
// `out` as bytes. Three input bytes at a time, four table lookups, no
// per-character `String::push`.
fn base64url_encode_into(input: &[u8], out: &mut Vec<u8>) {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut chunks = input.chunks_exact(3);
    for chunk in &mut chunks {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
        out.extend_from_slice(&[
            A[((n >> 18) & 63) as usize],
            A[((n >> 12) & 63) as usize],
            A[((n >> 6) & 63) as usize],
            A[(n & 63) as usize],
        ]);
    }
    match *chunks.remainder() {
        [b0] => {
            let n = (b0 as u32) << 16;
            out.extend_from_slice(&[A[((n >> 18) & 63) as usize], A[((n >> 12) & 63) as usize]]);
        }
        [b0, b1] => {
            let n = ((b0 as u32) << 16) | ((b1 as u32) << 8);
            out.extend_from_slice(&[
                A[((n >> 18) & 63) as usize],
                A[((n >> 12) & 63) as usize],
                A[((n >> 6) & 63) as usize],
            ]);
        }
        _ => {}
    }
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
            assert_eq!(v["skipped"], json!(false));
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

    /// The delivery verdict every sender of a message returns
    /// (docs/building-blocks.md): one email is one part, and its actions
    /// are the action links in the body. The engine records a send from it.
    #[test]
    fn the_verdict_counts_one_part_and_the_action_links_in_the_body() {
        host::http::respond(200, r#"{"id":"x","threadId":"y"}"#);
        let html = "<p>Done? <a href=\"https://talos.example.test/action-links/aaaa\">done</a> \
                    <a href=\"https://talos.example.test/action-links/bbbb\">drop</a> \
                    <a href=\"#\">unminted</a> <a href=\"mailto:x@example.com\">fallback</a></p>";
        let v = send(config(), json!({ "subject": "s", "html": html })).unwrap();
        for (field, want) in [
            ("provider", json!("gmail")),
            ("sent", json!(true)),
            ("skipped", json!(false)),
            ("dry_run", json!(false)),
            ("parts_total", json!(1)),
            ("parts_sent", json!(1)),
            ("actions_sent", json!(2)),
        ] {
            assert_eq!(v[field], want, "{field}: {v}");
        }
        // A body with nothing to act on.
        let v = send(config(), json!({ "subject": "s", "html": "<p>b</p>" })).unwrap();
        assert_eq!(v["actions_sent"], json!(0));

        // A dry run reports what would have left, and that nothing did.
        let mut dry = config();
        dry["DRY_RUN"] = json!(true);
        let v = send(dry, json!({ "subject": "s", "html": html })).unwrap();
        assert_eq!(
            (v["provider"].clone(), v["sent"].clone(), v["parts_total"].clone(), v["parts_sent"].clone(), v["actions_sent"].clone()),
            (json!("gmail"), json!(false), json!(1), json!(0), json!(2)),
            "{v}"
        );
        // A skip composed nothing.
        let v = send(config(), json!({ "skip": true })).unwrap();
        assert_eq!(
            (v["provider"].clone(), v["parts_total"].clone(), v["parts_sent"].clone(), v["actions_sent"].clone()),
            (json!("gmail"), json!(0), json!(0), json!(0)),
            "{v}"
        );
        // The count stops at the verdict's bound, so no body makes the send unrecordable.
        assert_eq!(count_action_links(&ACTION_LINK_PATH.repeat(2000)), MAX_ACTIONS_REPORTED);
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

    /// RFC 4648 section 10's vectors, unpadded: every remainder length.
    #[test]
    fn the_encoder_matches_the_published_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            let mut out = Vec::new();
            base64url_encode_into(plain.as_bytes(), &mut out);
            assert_eq!(String::from_utf8(out).unwrap(), encoded, "{plain}");
        }
        // The two characters that differ from standard base64.
        let mut out = Vec::new();
        base64url_encode_into(&[0xfb, 0xff, 0xfe], &mut out);
        assert_eq!(out, b"-__-");
    }

    /// The composer's other fields are skipped, whatever they hold, and a
    /// field of the wrong type where a string belongs reads as absent.
    #[test]
    fn fields_the_module_does_not_read_do_not_disturb_it() {
        host::http::respond(200, r#"{"id":"x"}"#);
        let v = send(
            config(),
            json!({
                "subject": "s",
                "html": "<p>b</p>",
                "notification": { "title": "t", "actions": [1, 2, { "deep": [null] }] },
                "__action_links_report__": { "minted": 2 },
                "rows": [[1, 2], [3, 4]],
            }),
        )
        .unwrap();
        assert_eq!(v["sent"], json!(true));
        assert!(sent_message().ends_with("\r\n\r\n<p>b</p>"));

        // `subject` as an object is "no subject given", not a parse failure.
        let mut dry = config();
        dry["DRY_RUN"] = json!(true);
        let v = send(dry, json!({ "subject": { "text": "s" }, "html": "<p>b</p>" })).unwrap();
        assert_eq!(v["subject"], json!("(no subject)"));
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
