// Canonical catalog module: create a Cloud Monitoring pubsub notification
// channel (Phase C self-serve provisioning — the automation of
// docs/gcp-push-setup.md step 3). Uses the WRITE-tier vault:// header
// resolution for auth — no direct secrets::get_secret calls.
//
// The notificationChannels POST is NOT idempotent (every POST mints a new
// channel), so this module first GETs the existing pubsub channels and
// matches labels.topic client-side — a re-run finds the prior channel and
// returns already_existed=true instead of creating a duplicate.

use serde::Deserialize;
use talos_sdk_macros::talos_module;

const MAX_ERROR_EXCERPT_CHARS: usize = 500;
const MAX_DISPLAY_NAME_CHARS: usize = 100;
const LIST_PAGE_SIZE: usize = 200;

// Typed decoders (NOT top-level serde_json::Value — 3-10x cheaper in WASM fuel).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListChannelsResp {
    notification_channels: Option<Vec<Channel>>,
}

#[derive(Deserialize)]
struct Channel {
    #[serde(default)]
    name: String,
    #[serde(default)]
    labels: ChannelLabels,
}

#[derive(Deserialize, Default)]
struct ChannelLabels {
    #[serde(default)]
    topic: String,
}

/// Validate a GCP project id: `^[a-z][a-z0-9-]{4,28}[a-z0-9]$`.
/// The value interpolates into the request PATH — reject anything else.
fn validate_project_id(id: &str) -> Result<(), String> {
    let bytes = id.as_bytes();
    let ok = bytes.len() >= 6
        && bytes.len() <= 30
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "PROJECT_ID '{}' is invalid: must match ^[a-z][a-z0-9-]{{4,28}}[a-z0-9]$ \
             (6-30 chars, lowercase letters / digits / hyphens, starts with a letter, \
             does not end with a hyphen)",
            excerpt(id)
        ))
    }
}

/// Validate a Pub/Sub short resource name (topic):
/// `^[A-Za-z][A-Za-z0-9._~+%-]{2,254}$` and must NOT start with "goog".
fn validate_pubsub_short_name(name: &str, field: &str) -> Result<(), String> {
    if name.starts_with("goog") {
        return Err(format!("{} must not start with 'goog' (reserved prefix)", field));
    }
    let bytes = name.as_bytes();
    let ok = bytes.len() >= 3
        && bytes.len() <= 255
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..].iter().all(|b| {
            b.is_ascii_alphanumeric() || matches!(*b, b'.' | b'_' | b'~' | b'+' | b'%' | b'-')
        });
    if ok {
        Ok(())
    } else {
        Err(format!(
            "{} '{}' is invalid: must match ^[A-Za-z][A-Za-z0-9._~+%-]{{2,254}}$ \
             (3-255 chars, starts with a letter)",
            field,
            excerpt(name)
        ))
    }
}

/// Strip control characters and cap at MAX_DISPLAY_NAME_CHARS (char-boundary-safe).
fn sanitize_display_name(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control())
        .take(MAX_DISPLAY_NAME_CHARS)
        .collect()
}

/// Char-boundary-safe excerpt, capped at MAX_ERROR_EXCERPT_CHARS characters.
/// Used for error bodies + bad config values. NEVER pass the auth header here.
fn excerpt(s: &str) -> String {
    s.chars().take(MAX_ERROR_EXCERPT_CHARS).collect()
}

/// Percent-encode a query-string value (RFC 3986 unreserved set kept as-is).
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

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let config = data.get("config").unwrap_or(&serde_json::Value::Null);
    let auth = config["AUTH_HEADER"].as_str().ok_or(
        "Missing AUTH_HEADER config (expected 'Bearer vault://oauth/google_cloud_write/{user_id}/{provider_key}/access_token')",
    )?;
    let project_id = config["PROJECT_ID"]
        .as_str()
        .ok_or("Missing PROJECT_ID config")?;
    let topic_name = config["TOPIC_NAME"]
        .as_str()
        .ok_or("Missing TOPIC_NAME config")?;
    let display_name = sanitize_display_name(
        config["DISPLAY_NAME"].as_str().unwrap_or("Talos incidents"),
    );
    if display_name.is_empty() {
        return Err("DISPLAY_NAME is empty after stripping control characters".to_string());
    }

    validate_project_id(project_id)?;
    validate_pubsub_short_name(topic_name, "TOPIC_NAME")?;

    let full_topic = format!("projects/{}/topics/{}", project_id, topic_name);
    let base_url = format!(
        "https://monitoring.googleapis.com/v3/projects/{}/notificationChannels",
        project_id
    );
    let auth_headers = vec![
        ("Authorization".to_string(), auth.to_string()),
        ("Accept".to_string(), "application/json".to_string()),
    ];

    // ── Pre-check: does a pubsub channel for this topic already exist? ──────
    // POST is NOT idempotent, so this lookup is what makes re-runs safe.
    let list_url = format!(
        "{}?filter={}&pageSize={}",
        base_url,
        pct("type=\"pubsub\""),
        LIST_PAGE_SIZE
    );
    let list_req = talos::core::http::Request {
        method: talos::core::http::Method::Get,
        url: list_url,
        headers: auth_headers.clone(),
        body: vec![],
        timeout_ms: Some(15000),
    };
    let list_resp =
        talos::core::http::fetch(&list_req).map_err(|e| format!("channel list fetch: {:?}", e))?;
    if list_resp.status == 401 {
        return Err(
            "GCP 401: write-tier access_token invalid or expired. Re-consent via /api/gcp/connect-write or call refresh_oauth_token on the oauth/google_cloud_write vault path."
                .to_string(),
        );
    }
    if !(200..300).contains(&list_resp.status) {
        let body = String::from_utf8_lossy(&list_resp.body).into_owned();
        return Err(format!(
            "GCP Monitoring HTTP {} (channel pre-check): {}",
            list_resp.status,
            excerpt(&body)
        ));
    }
    let list_body =
        String::from_utf8(list_resp.body).map_err(|_| "channel list: invalid utf8 response")?;
    let listed: ListChannelsResp =
        serde_json::from_str(&list_body).map_err(|e| format!("channel list parse: {}", e))?;
    if let Some(existing) = listed
        .notification_channels
        .unwrap_or_default()
        .into_iter()
        .find(|c| c.labels.topic == full_topic)
    {
        let result = serde_json::json!({
            "created": false,
            "already_existed": true,
            "channel_name": existing.name,
            "topic": full_topic,
        });
        return serde_json::to_string(&result).map_err(|e| e.to_string());
    }

    // ── Create the channel ───────────────────────────────────────────────────
    let body = serde_json::json!({
        "type": "pubsub",
        "displayName": display_name,
        "labels": { "topic": full_topic },
    });
    let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;

    let mut create_headers = auth_headers;
    create_headers.push(("Content-Type".to_string(), "application/json".to_string()));
    let create_req = talos::core::http::Request {
        method: talos::core::http::Method::Post,
        url: base_url,
        headers: create_headers,
        body: body_bytes,
        timeout_ms: Some(15000),
    };
    let create_resp = talos::core::http::fetch(&create_req)
        .map_err(|e| format!("channel create fetch: {:?}", e))?;
    if create_resp.status == 401 {
        return Err(
            "GCP 401: write-tier access_token invalid or expired. Re-consent via /api/gcp/connect-write or call refresh_oauth_token on the oauth/google_cloud_write vault path."
                .to_string(),
        );
    }
    if !(200..300).contains(&create_resp.status) {
        let body = String::from_utf8_lossy(&create_resp.body).into_owned();
        return Err(format!(
            "GCP Monitoring HTTP {} (channel create): {}",
            create_resp.status,
            excerpt(&body)
        ));
    }
    let create_body =
        String::from_utf8(create_resp.body).map_err(|_| "channel create: invalid utf8 response")?;
    let created: Channel =
        serde_json::from_str(&create_body).map_err(|e| format!("channel create parse: {}", e))?;

    let result = serde_json::json!({
        "created": true,
        "already_existed": false,
        "channel_name": created.name,
        "topic": full_topic,
    });
    serde_json::to_string(&result).map_err(|e| e.to_string())
}
