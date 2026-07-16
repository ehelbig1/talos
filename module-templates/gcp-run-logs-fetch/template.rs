// Canonical catalog module: FETCH the logs of a Cloud Run Job Execution from
// Cloud Logging (Phase D impersonated-token path). Companion to `GCP: Run Cloud
// Run Job` + `GCP: Poll Job Execution` — once an execution is done, this reads
// its stdout/stderr entries via `POST https://logging.googleapis.com/v2/entries:list`.
//
// IMPORTANT: this hits logging.googleapis.com — a DIFFERENT host than
// run.googleapis.com. The minted impersonated token's service account needs
// roles/logging.viewer (the docs/gcp-impersonation-setup.md bootstrap grants
// it). Auth is the Phase D minted-token path: the controller mints a ~10-min
// impersonated SA access token at dispatch and injects it under the requested
// `gcp/impersonated/<sa_email>/access_token` vault path; this module passes the
// AUTH_HEADER through verbatim. No direct secrets access.

use serde::Deserialize;
use talos_sdk_macros::talos_module;

const MAX_ERROR_EXCERPT_CHARS: usize = 500;
const MAX_ENTRY_TEXT_CHARS: usize = 2000;
const DEFAULT_MAX_ENTRIES: u32 = 50;
const MIN_ENTRIES: u32 = 1;
const MAX_ENTRIES_CAP: u32 = 200;

// Typed decoders. jsonPayload is genuinely arbitrary structured JSON, so it is
// the one field kept as serde_json::Value — this is NOT a top-level Value parse
// of the response, which is what the WASM fuel rule forbids.
#[derive(Deserialize)]
struct EntriesListResp {
    #[serde(default)]
    entries: Option<Vec<LogEntry>>,
}

#[derive(Deserialize)]
struct LogEntry {
    #[serde(default)]
    timestamp: String,
    #[serde(default)]
    severity: String,
    #[serde(rename = "textPayload", default)]
    text_payload: Option<String>,
    #[serde(rename = "jsonPayload", default)]
    json_payload: Option<serde_json::Value>,
}

/// Validate a GCP project id: `^[a-z][a-z0-9-]{4,28}[a-z0-9]$`.
/// The value interpolates into the request PATH / filter — reject anything else.
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

/// Validate a GCP region: `^[a-z]+-[a-z]+[0-9]$` (e.g. us-central1, europe-west1).
/// Unused in the Logging filter but validated for symmetry with the run/poll
/// modules — reject anything else.
fn validate_region(region: &str) -> Result<(), String> {
    let err = || {
        format!(
            "REGION '{}' is invalid: must match ^[a-z]+-[a-z]+[0-9]$ \
             (e.g. us-central1, europe-west1)",
            excerpt(region)
        )
    };
    let (a, b) = region.split_once('-').ok_or_else(err)?;
    let a_ok = !a.is_empty() && a.bytes().all(|x| x.is_ascii_lowercase());
    let bb = b.as_bytes();
    let b_ok = bb.len() >= 2
        && bb[bb.len() - 1].is_ascii_digit()
        && bb[..bb.len() - 1].iter().all(|x| x.is_ascii_lowercase());
    if a_ok && b_ok {
        Ok(())
    } else {
        Err(err())
    }
}

/// Validate a Cloud Run resource name (job / execution short id):
/// `^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$` — 1-63 chars, lowercase letters / digits
/// / hyphens, starts with a letter, no leading/trailing hyphen.
/// The value interpolates into the Logging filter — reject anything else (this
/// also closes filter-injection, since a valid name has no quotes/spaces).
fn validate_run_name(name: &str, field: &str) -> Result<(), String> {
    let err = || {
        format!(
            "{} '{}' is invalid: must match ^[a-z]([-a-z0-9]{{0,61}}[a-z0-9])?$ \
             (Cloud Run resource name: 1-63 chars, lowercase letters / digits / hyphens, \
             starts with a letter, no leading or trailing hyphen)",
            field,
            excerpt(name)
        )
    };
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 || !bytes[0].is_ascii_lowercase() {
        return Err(err());
    }
    if bytes.len() == 1 {
        return Ok(());
    }
    let last = bytes[bytes.len() - 1];
    if !(last.is_ascii_lowercase() || last.is_ascii_digit()) {
        return Err(err());
    }
    if bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        Ok(())
    } else {
        Err(err())
    }
}

/// Char-boundary-safe excerpt, capped at MAX_ERROR_EXCERPT_CHARS characters.
/// Used for error bodies + bad config values. NEVER pass the auth header here.
fn excerpt(s: &str) -> String {
    s.chars().take(MAX_ERROR_EXCERPT_CHARS).collect()
}

/// Char-boundary-safe cap at MAX_ENTRY_TEXT_CHARS characters.
fn cap_entry_text(s: &str) -> String {
    s.chars().take(MAX_ENTRY_TEXT_CHARS).collect()
}

/// Last path segment of a possibly-full resource name (short execution id).
fn last_segment(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

/// Resolve MAX_ENTRIES from config (number or numeric string), clamped to
/// [MIN_ENTRIES, MAX_ENTRIES_CAP]; defaults to DEFAULT_MAX_ENTRIES.
fn resolve_max_entries(config: &serde_json::Value) -> u32 {
    let raw = config
        .get("MAX_ENTRIES")
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok())))
        .unwrap_or(DEFAULT_MAX_ENTRIES as u64);
    // Clamp in u64 BEFORE narrowing — casting first would wrap a value above
    // u32::MAX down into range (e.g. 2^32+5 → 5) instead of clamping to the
    // cap (integer-wraparound class, lint check 21).
    raw.clamp(MIN_ENTRIES as u64, MAX_ENTRIES_CAP as u64) as u32
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let config = data.get("config").unwrap_or(&serde_json::Value::Null);
    let auth = config["AUTH_HEADER"].as_str().ok_or(
        "Missing AUTH_HEADER config (expected 'Bearer vault://gcp/impersonated/{sa_email}/access_token')",
    )?;
    let project_id = config["PROJECT_ID"]
        .as_str()
        .ok_or("Missing PROJECT_ID config")?;
    let region = config["REGION"].as_str().ok_or("Missing REGION config")?;
    let job_name = config["JOB_NAME"]
        .as_str()
        .ok_or("Missing JOB_NAME config")?;
    let execution_raw = config["EXECUTION_NAME"]
        .as_str()
        .ok_or("Missing EXECUTION_NAME config (the execution_id from 'GCP: Run Cloud Run Job')")?;
    let execution_name = last_segment(execution_raw);

    validate_project_id(project_id)?;
    validate_region(region)?;
    validate_run_name(job_name, "JOB_NAME")?;
    validate_run_name(execution_name, "EXECUTION_NAME")?;

    let max_entries = resolve_max_entries(config);

    // Filter is built ONLY from validated names — a valid Cloud Run name has no
    // quotes/spaces, so there is no way to break out of the quoted filter terms.
    let filter = format!(
        "resource.type=\"cloud_run_job\" AND resource.labels.job_name=\"{}\" AND \
         labels.\"run.googleapis.com/execution_name\"=\"{}\"",
        job_name, execution_name
    );
    let body = serde_json::json!({
        "resourceNames": [format!("projects/{}", project_id)],
        "filter": filter,
        "orderBy": "timestamp desc",
        "pageSize": max_entries,
    });
    let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;

    let req = talos::core::http::Request {
        method: talos::core::http::Method::Post,
        url: "https://logging.googleapis.com/v2/entries:list".to_string(),
        headers: vec![
            ("Authorization".to_string(), auth.to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: body_bytes,
        timeout_ms: Some(15000),
    };
    let resp = talos::core::http::fetch(&req).map_err(|e| format!("logs fetch: {:?}", e))?;

    if resp.status == 401 {
        return Err(
            "GCP 401: impersonated access token invalid or expired. The controller mints a \
             short-lived impersonated SA token under gcp/impersonated/<sa_email>/access_token \
             at dispatch — re-consent via /api/gcp/connect-full or call refresh_oauth_token on \
             the underlying full-tier Google Cloud vault path, then retry. (Logs also require \
             the runner SA to hold roles/logging.viewer.)"
                .to_string(),
        );
    }
    if !(200..300).contains(&resp.status) {
        let body = String::from_utf8_lossy(&resp.body).into_owned();
        return Err(format!(
            "GCP Cloud Logging HTTP {} (entries:list): {}",
            resp.status,
            excerpt(&body)
        ));
    }

    let body_str = String::from_utf8(resp.body).map_err(|_| "logs fetch: invalid utf8 response")?;
    let parsed: EntriesListResp =
        serde_json::from_str(&body_str).map_err(|e| format!("logs fetch parse: {}", e))?;

    // The API returns newest-first (orderBy timestamp desc); reverse to
    // chronological for readability.
    let mut entries = parsed.entries.unwrap_or_default();
    entries.reverse();

    let out_entries: Vec<serde_json::Value> = entries
        .into_iter()
        .map(|e| {
            let text = match e.text_payload {
                Some(t) if !t.is_empty() => cap_entry_text(&t),
                _ => match e.json_payload {
                    Some(j) => cap_entry_text(&serde_json::to_string(&j).unwrap_or_default()),
                    None => String::new(),
                },
            };
            serde_json::json!({
                "timestamp": e.timestamp,
                "severity": e.severity,
                "text": text,
            })
        })
        .collect();

    let count = out_entries.len();
    let result = serde_json::json!({
        "entries": out_entries,
        "count": count,
    });
    serde_json::to_string(&result).map_err(|e| e.to_string())
}
