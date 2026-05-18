// SECURITY: Inline-compiled modules that accept issue_key or repo_name from upstream
// input MUST validate them before interpolating into URLs. Apply these validators
// on next recompilation of: fetch-ticket-details, jira-transition-issue,
// check-github-repo, post-jira-comment.
//
// fn validate_issue_key(key: &str) -> bool {
//     let parts: Vec<&str> = key.split('-').collect();
//     parts.len() == 2
//         && !parts[0].is_empty()
//         && parts[0].chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
//         && !parts[1].is_empty()
//         && parts[1].chars().all(|c| c.is_ascii_digit())
// }
//
// fn validate_repo_name(name: &str) -> bool {
//     !name.is_empty()
//         && name.len() <= 100
//         && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
// }
//
// post-jira-comment hardening (apply on recompilation):
//   1. Cap draft_comment at 2000 chars: let comment = &draft_comment[..draft_comment.len().min(2000)];
//   2. Replace @ with (at) to prevent @mention spam: let comment = comment.replace('@', "(at)");

use talos_sdk_macros::talos_module;

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let config = data.get("config").unwrap_or(&serde_json::Value::Null);
    let jql = config["JQL"].as_str().ok_or("Missing JQL")?;
    let cloud_id = config["CLOUD_ID"].as_str().ok_or("Missing CLOUD_ID")?;
    if !validate_cloud_id(cloud_id) {
        return Err("Invalid CLOUD_ID: must be a UUID or hex string".to_string());
    }
    let auth_value = config["AUTH_HEADER"].as_str().ok_or("Missing AUTH_HEADER (use vault://path)")?;
    // allow-min-only-clamp: `as_u64()` returns Option<u64> — caller
    // can't supply a negative value because the type is unsigned.
    // The .min(100) upper bound is the only meaningful clamp here.
    let max_results = config["MAX_RESULTS"].as_u64().unwrap_or(25).min(100);
    let fields = config["FIELDS"].as_str().unwrap_or("summary,status,assignee,priority,updated,issuetype");
    let url = format!(
        "https://api.atlassian.com/ex/jira/{}/rest/api/3/search/jql?jql={}&maxResults={}&fields={}",
        cloud_id, pct(jql), max_results, pct(fields)
    );
    let req = talos::core::http::Request {
        method: talos::core::http::Method::Get,
        url,
        headers: vec![
            ("Authorization".to_string(), auth_value.to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: vec![],
        timeout_ms: Some(15000),
    };
    let resp = talos::core::http::fetch(&req).map_err(|e| format!("{:?}", e))?;
    let body = String::from_utf8(resp.body).map_err(|_| "bad utf8")?;
    if resp.status == 401 { return Err("Jira 401: token invalid or expired".to_string()); }
    if resp.status >= 400 { return Err(format!("Jira HTTP {}: {}", resp.status, &body[..200.min(body.len())])); }
    let j: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    let total = j["total"].as_u64().unwrap_or(0);
    let raw = j["issues"].as_array().cloned().unwrap_or_default();
    let issues: Vec<serde_json::Value> = raw.iter().map(|i| {
        let f = &i["fields"];
        serde_json::json!({
            "key": i["key"].as_str().unwrap_or(""),
            "summary": f["summary"].as_str().unwrap_or(""),
            "status": f["status"]["name"].as_str().unwrap_or(""),
            "assignee": f["assignee"]["displayName"].as_str().unwrap_or("Unassigned"),
            "priority": f["priority"]["name"].as_str().unwrap_or("None"),
            "updated": f["updated"].as_str().unwrap_or(""),
            "issuetype": f["issuetype"]["name"].as_str().unwrap_or("")
        })
    }).collect();
    let out = serde_json::json!({ "success": true, "issues": issues, "total": total, "jql": jql, "returned_count": issues.len() });
    serde_json::to_string(&out).map_err(|e| e.to_string())
}
fn pct(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() { o.push(b as char); }
        else if b == 45 || b == 95 || b == 46 || b == 126 { o.push(b as char); }
        else { o.push_str(&format!("%{:02X}", b)); }
    }
    o
}

/// Validates that cloud_id is a safe UUID/hex string (prevents path injection in Atlassian API URL).
fn validate_cloud_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Validates Jira issue key format: PROJECT-123 (for use by downstream modules).
#[allow(dead_code)]
fn validate_issue_key(key: &str) -> bool {
    let parts: Vec<&str> = key.split('-').collect();
    parts.len() == 2
        && !parts[0].is_empty()
        && parts[0].chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        && !parts[1].is_empty()
        && parts[1].chars().all(|c| c.is_ascii_digit())
}

/// Validates GitHub/repo name format (for use by downstream modules).
#[allow(dead_code)]
fn validate_repo_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}
