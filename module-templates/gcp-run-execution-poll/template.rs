// Canonical catalog module: POLL a Cloud Run Job Execution (Phase D
// impersonated-token path). Companion to `GCP: Run Cloud Run Job` — given the
// EXECUTION_NAME returned by the execute step, GETs the Execution resource and
// derives a coarse status (succeeded / failed / running).
//
// This module does NOT itself block. It is designed to be dropped inside a
// workflow wait-until-done loop (add_wait_node + a loop / confidence-gate that
// re-polls until `done` is true), so the workflow controls the cadence.
//
// Auth is the Phase D minted-token path: the controller mints a ~10-min
// impersonated service-account access token at dispatch and injects it under
// the requested `gcp/impersonated/<sa_email>/access_token` vault path; this
// module passes the AUTH_HEADER through verbatim. No direct secrets access.

use serde::Deserialize;
use talos_sdk_macros::talos_module;

const MAX_ERROR_EXCERPT_CHARS: usize = 500;

// Typed decoder (NOT top-level serde_json::Value — 3-10x cheaper in WASM fuel).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionResp {
    #[serde(default)]
    name: String,
    #[serde(default)]
    running_count: i64,
    #[serde(default)]
    succeeded_count: i64,
    #[serde(default)]
    failed_count: i64,
    #[serde(default)]
    cancelled_count: i64,
    #[serde(default)]
    completion_time: Option<String>,
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

/// Validate a GCP region: `^[a-z]+-[a-z]+[0-9]$` (e.g. us-central1, europe-west1).
/// The value interpolates into the request PATH — reject anything else.
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
/// The value interpolates into the request PATH — reject anything else.
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

/// Last path segment of a possibly-full resource name (short execution id).
fn last_segment(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
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
    // EXECUTION_NAME may be the short id or a full 'projects/.../executions/X'
    // resource path — extract the last segment either way.
    let execution_raw = config["EXECUTION_NAME"]
        .as_str()
        .ok_or("Missing EXECUTION_NAME config (the execution_id from 'GCP: Run Cloud Run Job')")?;
    let execution_name = last_segment(execution_raw);

    validate_project_id(project_id)?;
    validate_region(region)?;
    validate_run_name(job_name, "JOB_NAME")?;
    validate_run_name(execution_name, "EXECUTION_NAME")?;

    let url = format!(
        "https://run.googleapis.com/v2/projects/{}/locations/{}/jobs/{}/executions/{}",
        project_id, region, job_name, execution_name
    );
    let req = talos::core::http::Request {
        method: talos::core::http::Method::Get,
        url,
        headers: vec![
            ("Authorization".to_string(), auth.to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: Vec::new(),
        timeout_ms: Some(15000),
    };
    let resp = talos::core::http::fetch(&req).map_err(|e| format!("execution poll fetch: {:?}", e))?;

    if resp.status == 401 {
        return Err(
            "GCP 401: impersonated access token invalid or expired. The controller mints a \
             short-lived impersonated SA token under gcp/impersonated/<sa_email>/access_token \
             at dispatch — re-consent via /api/gcp/connect-full or call refresh_oauth_token on \
             the underlying full-tier Google Cloud vault path, then retry."
                .to_string(),
        );
    }
    if !(200..300).contains(&resp.status) {
        let body = String::from_utf8_lossy(&resp.body).into_owned();
        return Err(format!(
            "GCP Cloud Run HTTP {} (executions.get): {}",
            resp.status,
            excerpt(&body)
        ));
    }

    let body_str =
        String::from_utf8(resp.body).map_err(|_| "execution poll: invalid utf8 response")?;
    let exec: ExecutionResp =
        serde_json::from_str(&body_str).map_err(|e| format!("execution poll parse: {}", e))?;

    let completed = exec.completion_time.as_ref().map(|t| !t.is_empty()).unwrap_or(false);
    // Derive a coarse status. TERMINALITY is driven by `completionTime`: any
    // execution Cloud Run has finished with is done, regardless of counts. A
    // failed task is terminal even before the timestamp lands. Crucially, a
    // completed execution with NO successes (cancelled, or never scheduled due
    // to quota/permission — which increments `cancelledCount`, not
    // `failedCount`) must resolve to a terminal "failed", NOT "running" — else
    // a workflow wait-until-done loop (exit on done==true) never exits.
    let status = if exec.failed_count >= 1 {
        "failed"
    } else if completed && exec.succeeded_count >= 1 {
        "succeeded"
    } else if completed {
        // Completed with no successes and no failures = cancelled / stillborn.
        "failed"
    } else {
        "running"
    };
    let done = status != "running";

    let name = if exec.name.is_empty() {
        execution_name.to_string()
    } else {
        exec.name
    };
    let result = serde_json::json!({
        "status": status,
        "succeeded": exec.succeeded_count,
        "failed": exec.failed_count,
        "cancelled": exec.cancelled_count,
        "running": exec.running_count,
        "done": done,
        "execution": name,
    });
    serde_json::to_string(&result).map_err(|e| e.to_string())
}
