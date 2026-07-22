// Canonical catalog module: fetch ONE Gmail message (or a small labeled set)
// with the FULL detail an email-reply channel needs — the body text, the
// routing headers (To / Message-ID / In-Reply-To), the thread id, and a
// parsed Authentication-Results verdict (SPF / DKIM / DMARC) that a workflow
// gates sender trust on.
//
// Complements `gmail-list-messages`, which returns only lightweight metadata
// (id / subject / from / date / snippet) and never the body or the auth
// headers. This module is the "read the email my assistant was sent" leg of
// the email-your-assistant channel.
//
// SECURITY / DLP: this module handles message bodies, subjects, and sender
// addresses — all potential PII. It NEVER logs body_text, subject, from, or
// the OAuth token. Only counts are ever logged. Auth resolves through the
// `vault://` AUTH_HEADER pattern; the controller refreshes the token at
// dispatch time.
//
// SECURITY — Authentication-Results is only trustworthy when stamped by the
// RECEIVING authority (Gmail). An attacker can put their OWN
// `Authentication-Results: spf=pass; dkim=pass; dmarc=pass` header in the
// message they send; Gmail adds its own on top, and format=full returns BOTH.
// A naive substring match over the concatenated headers would match the
// forged one → false pass → a spoofed sender through the trust gate. We defend
// by PINNING the authserv-id: each Authentication-Results header value begins
// with the stamping authority's id (e.g. `mx.google.com; spf=pass ...`); we
// parse each header INDIVIDUALLY and only trust verdicts from a header whose
// authserv-id matches TRUSTED_AUTHSERV (default `google.com`, dot-boundary
// suffix match). Attacker-supplied headers carry a foreign authserv-id and are
// ignored.

use serde::Deserialize;
use serde_json::json;
use talos_sdk_macros::talos_module;

// Hard caps — a QUERY-mode fetch does one HTTP call per matched message, so
// keep the fan-out tight to stay inside the fuel budget.
const HARD_CAP: usize = 10;
const DEFAULT_MAX_RESULTS: usize = 5;
const DEFAULT_MAX_BODY_BYTES: usize = 16_384;
// The receiving authority whose Authentication-Results verdicts we trust.
// Gmail stamps `mx.google.com`; the dot-boundary suffix match accepts any
// `*.google.com` authserv-id while rejecting look-alikes (`notgoogle.com`).
const DEFAULT_TRUSTED_AUTHSERV: &str = "google.com";

// ── Gmail JSON (typed — NOT top-level Value walks; 3-10x cheaper in WASM) ──

#[derive(Deserialize)]
struct ListResp {
    messages: Option<Vec<ListMsg>>,
}

#[derive(Deserialize)]
struct ListMsg {
    id: String,
}

#[derive(Deserialize)]
struct FullMsg {
    id: String,
    #[serde(rename = "threadId")]
    thread_id: Option<String>,
    snippet: Option<String>,
    payload: Option<Part>,
}

#[derive(Deserialize)]
struct Part {
    #[serde(rename = "mimeType")]
    mime_type: Option<String>,
    headers: Option<Vec<Header>>,
    body: Option<PartBody>,
    parts: Option<Vec<Part>>,
}

#[derive(Deserialize)]
struct PartBody {
    data: Option<String>,
}

#[derive(Deserialize, Clone)]
struct Header {
    name: String,
    value: String,
}

// Parsed sender-authentication verdict. The workflow gates trust on this.
// `trusted` is true when at least one Authentication-Results header stamped by
// the TRUSTED_AUTHSERV authority was found; the pass booleans are computed
// ONLY from those trusted headers. `raw_present` means any AR header existed
// at all (trusted or not).
struct AuthResults {
    spf_pass: bool,
    dkim_pass: bool,
    dmarc_pass: bool,
    trusted: bool,
    raw_present: bool,
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    use talos::core::logging::{self, Level};

    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let config = data.get("config").unwrap_or(&serde_json::Value::Null);

    let auth = config["AUTH_HEADER"].as_str().ok_or(
        "Missing AUTH_HEADER config (expected 'Bearer vault://oauth/gmail/{user_id}/{email}/access_token')",
    )?;

    let max_body_bytes: usize = config["MAX_BODY_BYTES"]
        .as_u64()
        .map(|v| v as usize)
        .unwrap_or(DEFAULT_MAX_BODY_BYTES);

    // The receiving authority whose Authentication-Results we trust.
    let trusted_authserv = config["TRUSTED_AUTHSERV"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(DEFAULT_TRUSTED_AUTHSERV);

    // Two modes: explicit MESSAGE_ID, or QUERY + MAX_RESULTS.
    let message_id = config["MESSAGE_ID"].as_str().filter(|s| !s.is_empty());
    let query = config["QUERY"].as_str().filter(|s| !s.is_empty());

    let ids: Vec<String> = if let Some(mid) = message_id {
        vec![mid.to_string()]
    } else if let Some(q) = query {
        let max_results: usize = config["MAX_RESULTS"]
            .as_u64()
            .map(|v| v as usize)
            .unwrap_or(DEFAULT_MAX_RESULTS)
            .min(HARD_CAP)
            .max(1);
        list_ids(auth, q, max_results)?
    } else {
        return Err(
            "Provide either MESSAGE_ID (one message) or QUERY (e.g. 'label:Ask is:unread') in config"
                .to_string(),
        );
    };

    // DLP: log counts only — never the query, ids, subjects, or bodies.
    logging::log(
        Level::Info,
        &format!("gmail-get-message: fetching {} message(s)", ids.len()),
    );

    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        match fetch_full(auth, &id, max_body_bytes, trusted_authserv) {
            Ok(obj) => out.push(obj),
            Err(_) => continue, // best-effort: skip a message that fails to fetch/parse
        }
    }

    logging::log(
        Level::Info,
        &format!("gmail-get-message: returning {} message(s)", out.len()),
    );

    let result = json!({
        "count": out.len(),
        "messages": out,
    });
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

// List message ids for a Gmail search query.
fn list_ids(auth: &str, query: &str, max_results: usize) -> Result<Vec<String>, String> {
    let list_url = format!(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages?q={}&maxResults={}",
        pct(query),
        max_results
    );
    let req = talos::core::http::Request {
        method: talos::core::http::Method::Get,
        url: list_url,
        headers: vec![
            ("Authorization".to_string(), auth.to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: vec![],
        timeout_ms: Some(10000),
    };
    let resp = talos::core::http::fetch(&req).map_err(|e| format!("list fetch: {:?}", e))?;
    if resp.status == 401 {
        return Err("Gmail 401: access_token invalid or expired. Call refresh_oauth_token to force a refresh.".to_string());
    }
    if resp.status >= 400 {
        return Err(format!("Gmail list HTTP {}", resp.status));
    }
    let body_str = String::from_utf8(resp.body).map_err(|_| "list invalid utf8")?;
    let list: ListResp =
        serde_json::from_str(&body_str).map_err(|e| format!("list parse: {}", e))?;
    Ok(list
        .messages
        .unwrap_or_default()
        .into_iter()
        .take(max_results)
        .map(|m| m.id)
        .collect())
}

// Fetch one message with format=full and shape it into the output object.
fn fetch_full(
    auth: &str,
    id: &str,
    max_body_bytes: usize,
    trusted_authserv: &str,
) -> Result<serde_json::Value, String> {
    let url = format!(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/{}?format=full",
        id
    );
    let req = talos::core::http::Request {
        method: talos::core::http::Method::Get,
        url,
        headers: vec![
            ("Authorization".to_string(), auth.to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: vec![],
        timeout_ms: Some(15000),
    };
    let resp = talos::core::http::fetch(&req).map_err(|e| format!("fetch: {:?}", e))?;
    if resp.status >= 400 {
        return Err(format!("Gmail HTTP {}", resp.status));
    }
    let body_str = String::from_utf8(resp.body).map_err(|_| "invalid utf8")?;
    let msg: FullMsg = serde_json::from_str(&body_str).map_err(|e| format!("parse: {}", e))?;

    let payload = msg.payload;
    let headers: Vec<Header> = payload
        .as_ref()
        .and_then(|p| p.headers.clone())
        .unwrap_or_default();

    let mut from = String::new();
    let mut to = String::new();
    let mut subject = String::new();
    let mut date = String::new();
    let mut message_id_header = String::new();
    let mut in_reply_to = String::new();
    // Collect each Authentication-Results header value SEPARATELY — never
    // concatenate. A forged header (attacker-supplied) and the genuine one
    // (Gmail-stamped) must be judged independently by authserv-id.
    let mut auth_results: Vec<String> = Vec::new();
    for h in &headers {
        // Header names are case-insensitive per RFC 5322.
        if h.name.eq_ignore_ascii_case("From") {
            from = h.value.clone();
        } else if h.name.eq_ignore_ascii_case("To") {
            to = h.value.clone();
        } else if h.name.eq_ignore_ascii_case("Subject") {
            subject = h.value.clone();
        } else if h.name.eq_ignore_ascii_case("Date") {
            date = h.value.clone();
        } else if h.name.eq_ignore_ascii_case("Message-ID") {
            message_id_header = h.value.clone();
        } else if h.name.eq_ignore_ascii_case("In-Reply-To") {
            in_reply_to = h.value.clone();
        } else if h.name.eq_ignore_ascii_case("Authentication-Results") {
            auth_results.push(h.value.clone());
        }
    }

    let auth = parse_auth_results(&auth_results, trusted_authserv);

    // Body: prefer the text/plain MIME part, fall back to the snippet.
    let snippet = msg.snippet.clone().unwrap_or_default();
    let body_text = match payload.as_ref().and_then(find_text_plain) {
        Some(encoded) => {
            let decoded = base64url_decode(&encoded);
            let text = String::from_utf8_lossy(&decoded).into_owned();
            truncate_at_char_boundary(&text, max_body_bytes)
        }
        None => snippet.clone(),
    };

    Ok(json!({
        "id": msg.id,
        "thread_id": msg.thread_id.unwrap_or_default(),
        "message_id_header": message_id_header,
        "in_reply_to": in_reply_to,
        "from": from,
        "to": to,
        "subject": subject,
        "date": date,
        "snippet": snippet,
        "body_text": body_text,
        "auth": {
            "spf_pass": auth.spf_pass,
            "dkim_pass": auth.dkim_pass,
            "dmarc_pass": auth.dmarc_pass,
            "trusted": auth.trusted,
            "raw_present": auth.raw_present,
        },
    }))
}

// ── Pure helpers (unit-tested) ──────────────────────────────────────────────

// Parse Authentication-Results headers into pass/fail booleans, trusting ONLY
// verdicts stamped by the receiving authority (authserv-id pinning).
//
// SECURITY: `Authentication-Results` is only meaningful when added by the
// receiving server. An attacker can inject their own `Authentication-Results`
// header into the message they send; Gmail then stamps its own on top and
// format=full returns both. A substring match over the joined headers would
// match the forged verdict → false pass. We instead judge each header value
// INDEPENDENTLY by its authserv-id: the token before the first ';'. Only a
// header whose authserv-id equals `trusted_authserv` OR ends with
// `.trusted_authserv` (dot-boundary suffix — so `mx.google.com` matches
// `google.com` but `notgoogle.com` does not) is trusted; its verdicts (the
// part after the first ';') feed the booleans. Untrusted headers are ignored.
//
// `trusted` = at least one trusted header matched. `raw_present` = any AR
// header existed at all (trusted or not).
fn parse_auth_results(headers: &[String], trusted_authserv: &str) -> AuthResults {
    let raw_present = headers.iter().any(|h| !h.trim().is_empty());
    let trusted_lc = trusted_authserv.trim().to_ascii_lowercase();
    let suffix = format!(".{trusted_lc}");

    let mut spf_pass = false;
    let mut dkim_pass = false;
    let mut dmarc_pass = false;
    let mut trusted = false;

    if !trusted_lc.is_empty() {
        for value in headers {
            // Left of the first ';' is `authserv-id [version]`; right is the
            // verdict list. Take the first whitespace token of the left side
            // as the authserv-id (strips the optional RFC 8601 version).
            let mut parts = value.splitn(2, ';');
            let authserv_id = parts
                .next()
                .unwrap_or("")
                .trim()
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            let verdicts = parts.next().unwrap_or("");

            let is_trusted = !authserv_id.is_empty()
                && (authserv_id == trusted_lc || authserv_id.ends_with(&suffix));
            if !is_trusted {
                continue; // attacker-supplied or third-party header — do not trust
            }
            trusted = true;

            let lower = verdicts.to_ascii_lowercase();
            if lower.contains("spf=pass") {
                spf_pass = true;
            }
            if lower.contains("dkim=pass") {
                dkim_pass = true;
            }
            if lower.contains("dmarc=pass") {
                dmarc_pass = true;
            }
        }
    }

    AuthResults {
        spf_pass,
        dkim_pass,
        dmarc_pass,
        trusted,
        raw_present,
    }
}

// Recursively find the first text/plain part's base64url `data`.
fn find_text_plain(part: &Part) -> Option<String> {
    if let Some(mt) = &part.mime_type {
        if mt.eq_ignore_ascii_case("text/plain") {
            if let Some(b) = &part.body {
                if let Some(d) = &b.data {
                    if !d.is_empty() {
                        return Some(d.clone());
                    }
                }
            }
        }
    }
    if let Some(children) = &part.parts {
        for child in children {
            if let Some(found) = find_text_plain(child) {
                return Some(found);
            }
        }
    }
    None
}

// Pure-Rust base64url decoder (URL-safe alphabet, padding optional). Also
// tolerates standard '+' / '/' and skips whitespace/newlines. Avoids the
// `base64` crate, which isn't available in the WASM sandbox.
fn base64url_decode(input: &str) -> Vec<u8> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' | b'+' => Some(62),
            b'_' | b'/' => Some(63),
            _ => None, // '=', whitespace, newlines — skipped
        }
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 3);
    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    for &c in input.as_bytes() {
        if let Some(v) = val(c) {
            acc = (acc << 6) | v as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
    }
    out
}

// Truncate a string to at most `max_bytes`, walking back to the nearest UTF-8
// char boundary so we never split a multi-byte codepoint (panic class).
fn truncate_at_char_boundary(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

// Percent-encode a query string for the Gmail `q` parameter.
fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            out.push(c);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdrs(vs: &[&str]) -> Vec<String> {
        vs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn trusted_google_ar_passes() {
        let h = hdrs(&[
            "mx.google.com; spf=pass smtp.mailfrom=a@b.com; dkim=pass header.i=@b.com; dmarc=pass (p=REJECT)",
        ]);
        let a = parse_auth_results(&h, "google.com");
        assert!(a.spf_pass && a.dkim_pass && a.dmarc_pass);
        assert!(a.trusted);
        assert!(a.raw_present);
    }

    #[test]
    fn auth_results_case_insensitive() {
        // authserv-id and verdict tokens are both matched case-insensitively.
        let h = hdrs(&["MX.GOOGLE.COM; SPF=PASS; DKIM=Pass; DMARC=pass"]);
        let a = parse_auth_results(&h, "google.com");
        assert!(a.spf_pass && a.dkim_pass && a.dmarc_pass);
        assert!(a.trusted);
    }

    #[test]
    fn auth_results_partial_fail() {
        let h = hdrs(&["mx.google.com; spf=pass; dkim=fail; dmarc=fail"]);
        let a = parse_auth_results(&h, "google.com");
        assert!(a.spf_pass);
        assert!(!a.dkim_pass);
        assert!(!a.dmarc_pass);
        assert!(a.trusted);
    }

    #[test]
    fn auth_results_empty_is_absent() {
        let a = parse_auth_results(&[], "google.com");
        assert!(!a.spf_pass && !a.dkim_pass && !a.dmarc_pass);
        assert!(!a.trusted);
        assert!(!a.raw_present);
    }

    #[test]
    fn forged_untrusted_ar_is_ignored() {
        // Attacker embeds their OWN Authentication-Results in the sent message.
        // authserv-id is `evil.example.com`, not google.com → verdicts ignored.
        let h = hdrs(&["evil.example.com; spf=pass dkim=pass dmarc=pass"]);
        let a = parse_auth_results(&h, "google.com");
        assert!(!a.spf_pass && !a.dkim_pass && !a.dmarc_pass);
        assert!(!a.trusted);
        assert!(a.raw_present); // a header DID exist — just not a trusted one
    }

    #[test]
    fn authserv_id_suffix_boundary() {
        // Look-alike domain must NOT match the trusted authority.
        let notg = hdrs(&["notgoogle.com; spf=pass; dkim=pass; dmarc=pass"]);
        let a = parse_auth_results(&notg, "google.com");
        assert!(!a.trusted);
        assert!(!a.spf_pass && !a.dkim_pass && !a.dmarc_pass);

        // A genuine subdomain on the dot boundary MUST match.
        let g = hdrs(&["mx.google.com; spf=pass; dkim=pass; dmarc=pass"]);
        let b = parse_auth_results(&g, "google.com");
        assert!(b.trusted);
        assert!(b.spf_pass && b.dkim_pass && b.dmarc_pass);
    }

    #[test]
    fn mixed_forged_and_genuine() {
        // Two AR headers: a forged all-pass one + the genuine google one whose
        // real verdict is spf=pass but dkim/dmarc=fail. Verdicts must come ONLY
        // from the google header.
        let h = hdrs(&[
            "evil.example.com; spf=pass dkim=pass dmarc=pass",
            "mx.google.com; spf=pass smtp.mailfrom=x; dkim=fail; dmarc=fail",
        ]);
        let a = parse_auth_results(&h, "google.com");
        assert!(a.trusted);
        assert!(a.spf_pass); // from google
        assert!(!a.dkim_pass); // forged dkim=pass ignored
        assert!(!a.dmarc_pass); // forged dmarc=pass ignored
    }

    #[test]
    fn trusted_authserv_override() {
        // A self-hosted deployment behind its own MTA pins a different authority.
        let h = hdrs(&["mail.mycorp.example; spf=pass; dkim=pass; dmarc=pass"]);
        let a = parse_auth_results(&h, "mycorp.example");
        assert!(a.trusted);
        assert!(a.spf_pass && a.dkim_pass && a.dmarc_pass);
        // The default google pin would reject the same header.
        let b = parse_auth_results(&h, "google.com");
        assert!(!b.trusted);
    }

    #[test]
    fn base64url_decode_roundtrip() {
        // "Hello, world!" base64url (no padding).
        let decoded = base64url_decode("SGVsbG8sIHdvcmxkIQ");
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello, world!");
    }

    #[test]
    fn base64url_decode_with_padding_and_newlines() {
        // Same payload, standard-padded and with an injected newline.
        let decoded = base64url_decode("SGVsbG8sIHdv\ncmxkIQ==");
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello, world!");
    }

    #[test]
    fn base64url_decode_urlsafe_chars() {
        // Bytes 0xFB 0xFF encode to "-_8" in url-safe; ">?" region.
        let decoded = base64url_decode("--__");
        // "--__" => 62,62,63,63 => bytes 0xFB 0xEF 0xFF
        assert_eq!(decoded, vec![0xFB, 0xEF, 0xFF]);
    }

    #[test]
    fn find_text_plain_nested() {
        let part = Part {
            mime_type: Some("multipart/alternative".to_string()),
            headers: None,
            body: None,
            parts: Some(vec![
                Part {
                    mime_type: Some("text/html".to_string()),
                    headers: None,
                    body: Some(PartBody {
                        data: Some("aHRtbA".to_string()),
                    }),
                    parts: None,
                },
                Part {
                    mime_type: Some("text/plain".to_string()),
                    headers: None,
                    body: Some(PartBody {
                        data: Some("cGxhaW4".to_string()),
                    }),
                    parts: None,
                },
            ]),
        };
        assert_eq!(find_text_plain(&part).as_deref(), Some("cGxhaW4"));
    }

    #[test]
    fn find_text_plain_top_level() {
        let part = Part {
            mime_type: Some("text/plain".to_string()),
            headers: None,
            body: Some(PartBody {
                data: Some("Ym9keQ".to_string()),
            }),
            parts: None,
        };
        assert_eq!(find_text_plain(&part).as_deref(), Some("Ym9keQ"));
    }

    #[test]
    fn find_text_plain_none_when_absent() {
        let part = Part {
            mime_type: Some("text/html".to_string()),
            headers: None,
            body: Some(PartBody {
                data: Some("aHRtbA".to_string()),
            }),
            parts: None,
        };
        assert!(find_text_plain(&part).is_none());
    }

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate_at_char_boundary("hello", 100), "hello");
    }

    #[test]
    fn truncate_respects_char_boundary() {
        // "héllo": 'é' is 2 bytes (indices 1-2). Cutting at byte 2 splits it.
        let s = "héllo";
        let out = truncate_at_char_boundary(s, 2);
        assert_eq!(out, "h"); // walked back off the 'é' boundary
        assert!(out.is_char_boundary(out.len()));
    }

    #[test]
    fn truncate_exact_boundary() {
        let s = "héllo";
        // byte 3 is a valid boundary (after 'é').
        assert_eq!(truncate_at_char_boundary(s, 3), "hé");
    }
}
