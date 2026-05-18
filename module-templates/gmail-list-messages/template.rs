// Canonical catalog module: list Gmail messages matching a search query.
// Uses vault:// header resolution for auth — no direct secrets::get_secret calls.

use talos_sdk_macros::talos_module;
use serde::Deserialize;

const HARD_CAP: usize = 25;

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
            &body[..body.len().min(200)]
        ));
    }
    let body_str = String::from_utf8(list_resp.body).map_err(|_| "list invalid utf8")?;
    let list: ListResp = serde_json::from_str(&body_str).map_err(|e| format!("list parse: {}", e))?;
    let ids = list.messages.unwrap_or_default();

    let mut out = Vec::with_capacity(ids.len().min(max_results));
    for m in ids.into_iter().take(max_results) {
        let meta_url = format!(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/{}?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date",
            m.id
        );
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
        let mut from = String::new();
        let mut subject = String::new();
        let mut date = String::new();
        for h in headers {
            match h.name.as_str() {
                "From" => from = h.value,
                "Subject" => subject = h.value,
                "Date" => date = h.value,
                _ => {}
            }
        }
        out.push(serde_json::json!({
            "id": meta.id,
            "subject": subject,
            "from": from,
            "date": date,
            "snippet": meta.snippet.unwrap_or_default(),
        }));
    }

    let result = serde_json::json!({
        "count": out.len(),
        "messages": out,
        "query": query,
    });
    serde_json::to_string(&result).map_err(|e| e.to_string())
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
