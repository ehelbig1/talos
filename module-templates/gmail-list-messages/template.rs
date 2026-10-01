// Canonical catalog module: list Gmail messages matching a search query.
// Uses vault:// header resolution for auth — no direct secrets::get_secret calls.

use talos_sdk_macros::talos_module;
use serde::Deserialize;

const HARD_CAP: usize = 25;

/// Headers every message is fetched with; their output keys are fixed.
const DEFAULT_HEADERS: [&str; 3] = ["From", "Subject", "Date"];
/// Most extra headers one node may ask for.
const MAX_EXTRA_HEADERS: usize = 6;
/// Output keys an extra header may not take.
const RESERVED_KEYS: [&str; 5] = ["id", "subject", "from", "date", "snippet"];

#[derive(Deserialize)]
struct ListResp {
    messages: Option<Vec<ListMsg>>,
}

#[derive(Deserialize)]
struct ListMsg {
    id: String,
}

#[derive(Deserialize)]
struct Meta {
    id: String,
    snippet: Option<String>,
    payload: Option<MetaPayload>,
}

#[derive(Deserialize)]
struct MetaPayload {
    headers: Option<Vec<MetaHeader>>,
}

#[derive(Deserialize)]
struct MetaHeader {
    name: String,
    value: String,
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let config = data.get("config").unwrap_or(&serde_json::Value::Null);
    let auth = config["AUTH_HEADER"]
        .as_str()
        .ok_or("Missing AUTH_HEADER config (expected 'Bearer vault://oauth/gmail/{user_id}/{email}/access_token')")?;
    let query = config["QUERY"].as_str().unwrap_or("is:unread newer_than:24h");
    let max_results: usize = config["MAX_RESULTS"]
        .as_u64()
        .map(|v| v as usize)
        .unwrap_or(10)
        .min(HARD_CAP);

    let extra_headers = extra_headers(&config["EXTRA_HEADERS"])?;

    let list_url = format!(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages?q={}&maxResults={}",
        pct(query),
        max_results
    );
    let list_req = talos::core::http::Request {
        method: talos::core::http::Method::Get,
        url: list_url,
        headers: vec![
            ("Authorization".to_string(), auth.to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: vec![],
        timeout_ms: Some(10000),
    };
    let list_resp = talos::core::http::fetch(&list_req).map_err(|e| format!("list fetch: {:?}", e))?;
    if list_resp.status == 401 {
        return Err("Gmail 401: access_token invalid or expired. Call refresh_oauth_token to force a refresh and check the outcome.".to_string());
    }
    if list_resp.status >= 400 {
        let body = String::from_utf8(list_resp.body).unwrap_or_default();
        return Err(format!(
            "Gmail HTTP {}: {}",
            list_resp.status,
            head(&body, 200)
        ));
    }
    let body_str = String::from_utf8(list_resp.body).map_err(|_| "list invalid utf8")?;
    let list: ListResp = serde_json::from_str(&body_str).map_err(|e| format!("list parse: {}", e))?;
    let ids = list.messages.unwrap_or_default();

    let mut out = Vec::with_capacity(ids.len().min(max_results));
    for m in ids.into_iter().take(max_results) {
        let meta_url = metadata_url(&m.id, &extra_headers);
        let meta_req = talos::core::http::Request {
            method: talos::core::http::Method::Get,
            url: meta_url,
            headers: vec![
                ("Authorization".to_string(), auth.to_string()),
                ("Accept".to_string(), "application/json".to_string()),
            ],
            body: vec![],
            timeout_ms: Some(10000),
        };
        let meta_resp = match talos::core::http::fetch(&meta_req) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if meta_resp.status >= 400 {
            continue;
        }
        let meta_body = match String::from_utf8(meta_resp.body) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let meta: Meta = match serde_json::from_str(&meta_body) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let headers = meta.payload.and_then(|p| p.headers).unwrap_or_default();
        out.push(message_entry(
            meta.id,
            meta.snippet.unwrap_or_default(),
            headers,
            &extra_headers,
        ));
    }

    let result = serde_json::json!({
        "count": out.len(),
        "messages": out,
        "query": query,
    });
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

/// The extra headers a node asks for: an array of names, or one
/// comma-separated string. A name is letters, digits and `-` only (it goes
/// into the request URL), at most 40 characters. The three default headers
/// and repeats are dropped; a name whose output key would overwrite a fixed
/// field, a malformed name or too many names is an error rather than a
/// silently ignored setting.
fn extra_headers(value: &serde_json::Value) -> Result<Vec<String>, String> {
    let names: Vec<String> = match value {
        serde_json::Value::Null => Vec::new(),
        serde_json::Value::String(s) => s.split(',').map(|n| n.trim().to_string()).collect(),
        serde_json::Value::Array(items) => {
            let mut names = Vec::with_capacity(items.len());
            for item in items {
                match item.as_str() {
                    Some(n) => names.push(n.trim().to_string()),
                    None => {
                        return Err(
                            "EXTRA_HEADERS must be an array of header names (strings)".to_string()
                        )
                    }
                }
            }
            names
        }
        _ => {
            return Err(
                "EXTRA_HEADERS must be an array of header names or a comma-separated string"
                    .to_string(),
            )
        }
    };
    let mut out: Vec<String> = Vec::new();
    for name in names {
        if name.is_empty() {
            continue;
        }
        let well_formed = name.len() <= 40
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !well_formed {
            return Err(format!(
                "EXTRA_HEADERS: '{}' is not a header name (letters, digits and '-' only, at most 40 characters)",
                head(&name, 60)
            ));
        }
        if DEFAULT_HEADERS.iter().any(|d| d.eq_ignore_ascii_case(&name))
            || out.iter().any(|seen| seen.eq_ignore_ascii_case(&name))
        {
            continue;
        }
        if RESERVED_KEYS.contains(&output_key(&name).as_str()) {
            return Err(format!(
                "EXTRA_HEADERS: '{name}' would overwrite the '{}' field of each message",
                output_key(&name)
            ));
        }
        out.push(name);
    }
    if out.len() > MAX_EXTRA_HEADERS {
        return Err(format!(
            "EXTRA_HEADERS: at most {MAX_EXTRA_HEADERS} extra headers, got {}",
            out.len()
        ));
    }
    Ok(out)
}

/// The key an extra header is returned under: lower case, `-` as `_`
/// (`Reply-To` → `reply_to`).
fn output_key(header: &str) -> String {
    header.to_ascii_lowercase().replace('-', "_")
}

fn metadata_url(message_id: &str, extra: &[String]) -> String {
    let mut url = format!(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/{}?format=metadata",
        pct(message_id)
    );
    for name in DEFAULT_HEADERS.iter().copied().chain(extra.iter().map(String::as_str)) {
        url.push_str("&metadataHeaders=");
        url.push_str(name);
    }
    url
}

/// One message of the output. Header names are matched without regard to
/// case (a sender may write `FROM:`); an extra header the message does not
/// carry is the empty string, so every entry has the same keys.
fn message_entry(
    id: String,
    snippet: String,
    headers: Vec<MetaHeader>,
    extra: &[String],
) -> serde_json::Value {
    let mut entry = serde_json::Map::new();
    let find = |name: &str| {
        headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.clone())
            .unwrap_or_default()
    };
    entry.insert("id".to_string(), id.into());
    entry.insert("subject".to_string(), find("Subject").into());
    entry.insert("from".to_string(), find("From").into());
    entry.insert("date".to_string(), find("Date").into());
    entry.insert("snippet".to_string(), snippet.into());
    for name in extra {
        entry.insert(output_key(name), find(name).into());
    }
    serde_json::Value::Object(entry)
}

/// The first `max` bytes of `s`, cut on a character boundary.
fn head(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

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
    use serde_json::json;

    fn header(name: &str, value: &str) -> MetaHeader {
        MetaHeader {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn no_extra_headers_leaves_the_request_and_the_entry_as_before() {
        assert_eq!(extra_headers(&serde_json::Value::Null).unwrap(), Vec::<String>::new());
        assert_eq!(
            metadata_url("abc123", &[]),
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/abc123?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date"
        );
        let entry = message_entry(
            "abc123".into(),
            "hello".into(),
            vec![header("From", "a@example.com"), header("Subject", "s"), header("Date", "d")],
            &[],
        );
        assert_eq!(
            entry,
            json!({"id": "abc123", "subject": "s", "from": "a@example.com", "date": "d", "snippet": "hello"})
        );
    }

    #[test]
    fn extra_headers_are_requested_and_returned_under_lower_case_keys() {
        let extra = extra_headers(&json!(["To", "Reply-To", "to", "From"])).unwrap();
        assert_eq!(extra, vec!["To".to_string(), "Reply-To".to_string()]);
        assert!(metadata_url("m", &extra).ends_with("&metadataHeaders=To&metadataHeaders=Reply-To"));
        let entry = message_entry(
            "m".into(),
            String::new(),
            vec![header("to", "b@example.com"), header("FROM", "a@example.com")],
            &extra,
        );
        assert_eq!(entry["to"], json!("b@example.com"));
        assert_eq!(entry["from"], json!("a@example.com"));
        // Not on the message: present and empty, so every entry has the same keys.
        assert_eq!(entry["reply_to"], json!(""));
    }

    #[test]
    fn a_comma_separated_string_is_accepted() {
        assert_eq!(
            extra_headers(&json!("To, Cc ,")).unwrap(),
            vec!["To".to_string(), "Cc".to_string()]
        );
    }

    #[test]
    fn a_bad_setting_is_an_error_not_a_silent_no_op() {
        for bad in [
            json!(["To&metadataHeaders=X"]),
            json!(["a b"]),
            json!(["x".repeat(41)]),
            json!([1]),
            json!({"To": true}),
            json!(["Id"]),
            json!(["Snippet"]),
            json!(["A", "B", "C", "D", "E", "F", "G"]),
        ] {
            assert!(extra_headers(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_error_body_is_cut_on_a_character_boundary() {
        let body = "é".repeat(150); // 300 bytes, 2 per character
        assert_eq!(head(&body, 201).len(), 200);
        assert_eq!(head("short", 200), "short");
    }
}
