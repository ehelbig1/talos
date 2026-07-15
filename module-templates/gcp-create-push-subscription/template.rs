// Canonical catalog module: create a Google Cloud Pub/Sub PUSH subscription
// with OIDC-authenticated delivery (Phase C self-serve provisioning — the
// automation of docs/gcp-push-setup.md step 2). Uses the WRITE-tier vault://
// header resolution for auth — no direct secrets::get_secret calls.
// Idempotent: HTTP 409 (subscription already exists) is reported as SUCCESS
// with already_existed=true so re-runs are safe.

use serde::Deserialize;
use talos_sdk_macros::talos_module;

const MAX_ERROR_EXCERPT_CHARS: usize = 500;

// Typed decoder (NOT top-level serde_json::Value — 3-10x cheaper in WASM fuel).
#[derive(Deserialize)]
struct SubscriptionResp {
    #[serde(default)]
    name: String,
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

/// Validate a Pub/Sub short resource name (topic / subscription):
/// `^[A-Za-z][A-Za-z0-9._~+%-]{2,254}$` and must NOT start with "goog".
/// The value interpolates into the request PATH — reject anything else.
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

/// Pub/Sub push delivery requires an HTTPS endpoint.
fn validate_push_endpoint(url: &str) -> Result<(), String> {
    if url.starts_with("https://") && url.len() > "https://".len() {
        Ok(())
    } else {
        Err(format!(
            "PUSH_ENDPOINT '{}' is invalid: Pub/Sub push delivery requires an https:// URL",
            excerpt(url)
        ))
    }
}

/// Basic shape check: `^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$`.
fn validate_service_account_email(email: &str) -> Result<(), String> {
    let err = || {
        format!(
            "SERVICE_ACCOUNT_EMAIL '{}' is invalid: expected \
             <name>@<project>.iam.gserviceaccount.com (lowercase letters, digits, hyphens)",
            excerpt(email)
        )
    };
    let (local, domain) = email.split_once('@').ok_or_else(err)?;
    let sa_chars = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let project = domain.strip_suffix(".iam.gserviceaccount.com").ok_or_else(err)?;
    if sa_chars(local) && sa_chars(project) {
        Ok(())
    } else {
        Err(err())
    }
}

/// Audience must be a non-empty token with no whitespace.
fn validate_audience(audience: &str) -> Result<(), String> {
    if audience.is_empty() {
        return Err("AUDIENCE must not be empty".to_string());
    }
    if audience.chars().any(|c| c.is_whitespace()) {
        return Err("AUDIENCE must not contain whitespace".to_string());
    }
    Ok(())
}

/// Char-boundary-safe excerpt, capped at MAX_ERROR_EXCERPT_CHARS characters.
/// Used for error bodies + bad config values. NEVER pass the auth header here.
fn excerpt(s: &str) -> String {
    s.chars().take(MAX_ERROR_EXCERPT_CHARS).collect()
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
    let subscription_name = config["SUBSCRIPTION_NAME"]
        .as_str()
        .ok_or("Missing SUBSCRIPTION_NAME config")?;
    let push_endpoint = config["PUSH_ENDPOINT"]
        .as_str()
        .ok_or("Missing PUSH_ENDPOINT config (the Talos push URL from Settings → Google Cloud Watch Channels)")?;
    let service_account_email = config["SERVICE_ACCOUNT_EMAIL"]
        .as_str()
        .ok_or("Missing SERVICE_ACCOUNT_EMAIL config")?;
    let audience = config["AUDIENCE"]
        .as_str()
        .ok_or("Missing AUDIENCE config (must equal the controller's GCP_PUBSUB_AUDIENCE)")?;

    validate_project_id(project_id)?;
    validate_pubsub_short_name(topic_name, "TOPIC_NAME")?;
    validate_pubsub_short_name(subscription_name, "SUBSCRIPTION_NAME")?;
    validate_push_endpoint(push_endpoint)?;
    validate_service_account_email(service_account_email)?;
    validate_audience(audience)?;

    let full_subscription = format!("projects/{}/subscriptions/{}", project_id, subscription_name);
    let full_topic = format!("projects/{}/topics/{}", project_id, topic_name);
    let url = format!("https://pubsub.googleapis.com/v1/{}", full_subscription);

    let body = serde_json::json!({
        "topic": full_topic,
        "pushConfig": {
            "pushEndpoint": push_endpoint,
            "oidcToken": {
                "serviceAccountEmail": service_account_email,
                "audience": audience,
            },
        },
        "ackDeadlineSeconds": 60,
    });
    let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;

    let req = talos::core::http::Request {
        method: talos::core::http::Method::Put,
        url,
        headers: vec![
            ("Authorization".to_string(), auth.to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: body_bytes,
        timeout_ms: Some(15000),
    };
    let resp =
        talos::core::http::fetch(&req).map_err(|e| format!("subscription create fetch: {:?}", e))?;

    // 409 = subscription already exists → idempotent success for re-runs.
    if resp.status == 409 {
        let result = serde_json::json!({
            "created": false,
            "already_existed": true,
            "subscription": full_subscription,
            "topic": full_topic,
        });
        return serde_json::to_string(&result).map_err(|e| e.to_string());
    }
    if resp.status == 401 {
        return Err(
            "GCP 401: write-tier access_token invalid or expired. Re-consent via /api/gcp/connect-write or call refresh_oauth_token on the oauth/google_cloud_write vault path."
                .to_string(),
        );
    }
    if !(200..300).contains(&resp.status) {
        let body = String::from_utf8_lossy(&resp.body).into_owned();
        return Err(format!("GCP Pub/Sub HTTP {}: {}", resp.status, excerpt(&body)));
    }

    // 2xx — parse the returned Subscription resource for its canonical name.
    let body_str =
        String::from_utf8(resp.body).map_err(|_| "subscription create: invalid utf8 response")?;
    let sub: SubscriptionResp =
        serde_json::from_str(&body_str).map_err(|e| format!("subscription create parse: {}", e))?;
    let name = if sub.name.is_empty() { full_subscription } else { sub.name };

    let result = serde_json::json!({
        "created": true,
        "already_existed": false,
        "subscription": name,
        "topic": full_topic,
    });
    serde_json::to_string(&result).map_err(|e| e.to_string())
}
