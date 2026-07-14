// Canonical catalog module: list GCP projects via Cloud Resource Manager v3.
// Uses vault:// header resolution for auth — no direct secrets::get_secret calls.

use talos_sdk_macros::talos_module;
use serde::Deserialize;

const HARD_CAP: usize = 50;

// Typed decoders (NOT top-level serde_json::Value — 3-10x cheaper in WASM fuel).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchResp {
    projects: Option<Vec<Project>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Project {
    #[serde(default)]
    project_id: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    create_time: String,
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let config = data.get("config").unwrap_or(&serde_json::Value::Null);
    let auth = config["AUTH_HEADER"]
        .as_str()
        .ok_or("Missing AUTH_HEADER config (expected 'Bearer vault://oauth/google_cloud/{user_id}/{provider_key}/access_token')")?;
    let query = config["QUERY"].as_str().unwrap_or("state:ACTIVE");
    let max_results: usize = config["MAX_RESULTS"]
        .as_u64()
        .map(|v| v as usize)
        .unwrap_or(25)
        .clamp(1, HARD_CAP);

    let mut url = format!(
        "https://cloudresourcemanager.googleapis.com/v3/projects:search?pageSize={}",
        max_results
    );
    if !query.is_empty() {
        url.push_str("&query=");
        url.push_str(&pct(query));
    }

    let req = talos::core::http::Request {
        method: talos::core::http::Method::Get,
        url,
        headers: vec![
            ("Authorization".to_string(), auth.to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: vec![],
        timeout_ms: Some(10000),
    };
    let resp = talos::core::http::fetch(&req).map_err(|e| format!("search fetch: {:?}", e))?;
    if resp.status == 401 {
        return Err("GCP 401: access_token invalid or expired. Call refresh_oauth_token to force a refresh and check the outcome.".to_string());
    }
    if resp.status >= 400 {
        let body = String::from_utf8(resp.body).unwrap_or_default();
        return Err(format!(
            "GCP HTTP {}: {}",
            resp.status,
            &body[..body.len().min(200)]
        ));
    }
    let body_str = String::from_utf8(resp.body).map_err(|_| "search invalid utf8")?;
    let search: SearchResp =
        serde_json::from_str(&body_str).map_err(|e| format!("search parse: {}", e))?;
    let projects = search.projects.unwrap_or_default();

    let mut out = Vec::with_capacity(projects.len().min(max_results));
    for p in projects.into_iter().take(max_results) {
        out.push(serde_json::json!({
            "project_id": p.project_id,
            "display_name": p.display_name,
            "state": p.state,
            "create_time": p.create_time,
        }));
    }

    let result = serde_json::json!({
        "count": out.len(),
        "projects": out,
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
