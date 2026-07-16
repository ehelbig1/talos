// Canonical catalog module: EXECUTE a pre-created Cloud Run Job (Phase D
// impersonated-token path). This is "option 1" — the operator pre-creates a
// `talos-runner` Cloud Run Job once (see docs/gcp-impersonation-setup.md), and
// this module RUNS it (optionally overriding args/env per run) via
// `POST .../jobs/{JOB_NAME}:run`. It does NOT create or delete the job itself.
//
// Auth is the Phase D minted-token path: the controller mints a ~10-min
// impersonated service-account access token at dispatch time and injects it
// under the requested `gcp/impersonated/<sa_email>/access_token` vault path;
// this module passes the AUTH_HEADER through verbatim as the Authorization
// header. No direct secrets::get_secret calls.
//
// The `:run` call returns a google.longrunning.Operation whose metadata is the
// Execution resource — pair this module with `GCP: Poll Job Execution` and
// `GCP: Fetch Job Logs` to wait for completion and read the output.

use serde::Deserialize;
use talos_sdk_macros::talos_module;

const MAX_ERROR_EXCERPT_CHARS: usize = 500;

// Typed decoders (NOT top-level serde_json::Value — 3-10x cheaper in WASM fuel).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RunOperationResp {
    /// The operation resource name (projects/.../operations/...).
    #[serde(default)]
    name: String,
    /// The RunJob operation's metadata IS the Execution resource; its `name`
    /// is the full execution resource path.
    #[serde(default)]
    metadata: Option<OperationMetadata>,
}

#[derive(Deserialize, Default)]
struct OperationMetadata {
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
    // b = [a-z]+[0-9]: at least 2 chars, last is a digit, the rest lowercase,
    // and NO further hyphen (split_once only consumed the first one).
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

/// Parse the optional ARGS config into a Vec<String>, rejecting non-string
/// elements. ARGS maps to the container `args` override (replaces the job's
/// baked-in container args for this run).
fn parse_args(v: &serde_json::Value) -> Result<Vec<String>, String> {
    let arr = v
        .as_array()
        .ok_or("ARGS must be a JSON array of strings")?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let s = item
            .as_str()
            .ok_or_else(|| format!("ARGS[{}] must be a string", i))?;
        out.push(s.to_string());
    }
    Ok(out)
}

/// Parse the optional ENV config into a Vec of {name, value} objects, rejecting
/// non-flat / non-string values. ENV maps to the container `env` override.
fn parse_env(v: &serde_json::Value) -> Result<Vec<serde_json::Value>, String> {
    let obj = v
        .as_object()
        .ok_or("ENV must be a flat JSON object of string->string")?;
    let mut out = Vec::with_capacity(obj.len());
    for (k, val) in obj {
        let s = val
            .as_str()
            .ok_or_else(|| format!("ENV['{}'] must be a string value", excerpt(k)))?;
        out.push(serde_json::json!({ "name": k, "value": s }));
    }
    Ok(out)
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

    validate_project_id(project_id)?;
    validate_region(region)?;
    validate_run_name(job_name, "JOB_NAME")?;

    // COMMAND is reserved / not-yet-supported: the Cloud Run Admin API v2
    // RunJob overrides expose only a container `args` override, NOT an
    // entrypoint/command override, so honoring a COMMAND here would silently
    // do the wrong thing. Fail loud instead of dropping it.
    if config.get("COMMAND").map(|c| !c.is_null()).unwrap_or(false) {
        return Err(
            "COMMAND is reserved / not yet supported: the Cloud Run RunJob overrides API \
             only exposes a container `args` override (no entrypoint/command override). \
             Bake the entrypoint into the talos-runner job image and pass ARGS instead."
                .to_string(),
        );
    }

    // Build the per-run override body. If neither ARGS nor ENV is provided,
    // send an empty body so the job runs its baked-in command unchanged.
    let mut container = serde_json::Map::new();
    if let Some(args_v) = config.get("ARGS").filter(|v| !v.is_null()) {
        container.insert("args".to_string(), serde_json::json!(parse_args(args_v)?));
    }
    if let Some(env_v) = config.get("ENV").filter(|v| !v.is_null()) {
        container.insert("env".to_string(), serde_json::json!(parse_env(env_v)?));
    }
    let body_val = if container.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::json!({
            "overrides": {
                "containerOverrides": [serde_json::Value::Object(container)]
            }
        })
    };
    let body_bytes = serde_json::to_vec(&body_val).map_err(|e| e.to_string())?;

    let url = format!(
        "https://run.googleapis.com/v2/projects/{}/locations/{}/jobs/{}:run",
        project_id, region, job_name
    );
    let req = talos::core::http::Request {
        method: talos::core::http::Method::Post,
        url,
        headers: vec![
            ("Authorization".to_string(), auth.to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: body_bytes,
        timeout_ms: Some(15000),
    };
    let resp = talos::core::http::fetch(&req).map_err(|e| format!("job run fetch: {:?}", e))?;

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
            "GCP Cloud Run HTTP {} (jobs:run): {}",
            resp.status,
            excerpt(&body)
        ));
    }

    // 2xx — the response is a long-running Operation; metadata carries the
    // Execution resource name.
    let body_str = String::from_utf8(resp.body).map_err(|_| "job run: invalid utf8 response")?;
    let op: RunOperationResp =
        serde_json::from_str(&body_str).map_err(|e| format!("job run parse: {}", e))?;
    let execution = op.metadata.unwrap_or_default().name;
    let execution_id = last_segment(&execution).to_string();

    let result = serde_json::json!({
        "started": true,
        "operation": op.name,
        "execution": execution,
        "execution_id": execution_id,
        "project": project_id,
        "region": region,
        "job": job_name,
    });
    serde_json::to_string(&result).map_err(|e| e.to_string())
}
