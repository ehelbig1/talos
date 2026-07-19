use talos_sdk_macros::talos_module;

// Normalize ONE Cloud Monitoring incident into the ops-alerts store
// (the `__ops_alert__` envelope; persisted by the module-result
// completion chokepoint — see talos-ops-alerts-repository::envelope).
//
// Input: the google_cloud watch dispatch payload —
//   { "config": {...}, "data": { "incident": {...}, "incident_id",
//     "state", "watch_uuid", "received_at" } }
// (Cloud Monitoring publishes one notification per incident/state
// transition, so this module emits at most one alert per invocation.)
//
// Dedup identity is `policy + resource`, NOT `incident_id`: Monitoring
// mints a fresh incident_id every time a condition re-fires, and the
// triage store's whole point is one rolling alert per condition that
// bumps `occurrence_count` (and reopens after resolve) — the same
// philosophy as the email normalizer's per-org Snyk rolling alert. The
// latest incident_id is kept as `external_id` for console lookup.
//
// Severity hint maps the alert policy's declared severity
// (CRITICAL → critical, ERROR → high, WARNING → medium); unknown or
// absent stays unclassified. Hints apply on first ingest only — the
// classifier pass and human corrections own severity after that.
//
// Everything is typed-struct parsed per the WASM fuel rules.

#[derive(serde::Deserialize)]
struct Envelope {
    #[serde(default)]
    config: Config,
    // GCP watch dispatch shape: {config, data: {incident, incident_id, state}}.
    #[serde(default)]
    data: Option<Data>,
    // Inbound-webhook shape: {config, input: <posted body>} — the router
    // wraps the raw POST body under `input` (trigger-input escape-hatch
    // pattern, DX pain point #13). Lets a plain webhook stand in for the
    // Pub/Sub watch (e.g. before a public push endpoint exists).
    #[serde(default)]
    input: Option<Data>,
    // Tolerate the incident arriving at the top level (direct testing).
    #[serde(default)]
    incident: Option<Incident>,
}

#[derive(serde::Deserialize, Default)]
struct Config {
    #[serde(default, rename = "SOURCE_PREFIX")]
    source_prefix: String,
    /// Legacy toggle (pre-ON_CLOSED): `true` maps to `ingest`.
    #[serde(default, rename = "INCLUDE_CLOSED")]
    include_closed: bool,
    /// What a `state: "closed"` notification does:
    ///   "resolve" (default) — emit a `status_event: "resolved"` entry so
    ///     the rolling alert auto-resolves (`resolved_source = 'signal'`);
    ///   "ignore" — skip the notification entirely (old default);
    ///   "ingest" — treat it as a normal alert event (bumps the row).
    #[serde(default, rename = "ON_CLOSED")]
    on_closed: String,
}

#[derive(serde::Deserialize, Default)]
struct Data {
    #[serde(default)]
    incident: Option<Incident>,
    #[serde(default)]
    incident_id: String,
    #[serde(default)]
    state: String,
}

#[derive(serde::Deserialize, Default)]
struct Incident {
    // Fallback when the caller didn't hoist incident_id to the data
    // level (webhook-shaped input; the GCP watch dispatch hoists it,
    // tolerating id-as-number — inside the incident body it's a string).
    #[serde(default)]
    incident_id: String,
    #[serde(default)]
    policy_name: String,
    #[serde(default)]
    condition_name: String,
    #[serde(default)]
    resource_display_name: String,
    #[serde(default)]
    resource_name: String,
    #[serde(default)]
    scoping_project_id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    url: String,
    // Google emits these as strings in v1.2 payloads but client
    // libraries have been seen sending numbers — accept either.
    #[serde(default)]
    observed_value: serde_json::Value,
    #[serde(default)]
    threshold_value: serde_json::Value,
}

fn norm_key(s: &str) -> String {
    // Lowercase + collapse non-alphanumerics so cosmetic renames don't
    // split the rolling alert. (No digit-stripping here, unlike the
    // email normalizer: policy/resource names are stable identifiers,
    // and short numbers in them — "disk-2" — ARE identity.)
    let mut out = String::with_capacity(s.len());
    let mut last_dash = false;
    for c in s.trim().to_lowercase().chars() {
        if c.is_alphanumeric() {
            out.push(c);
            last_dash = false;
        } else if !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
    }
    out.trim_matches('-').chars().take(180).collect()
}

fn severity_hint(policy_severity: &str) -> &'static str {
    match policy_severity.to_ascii_uppercase().as_str() {
        "CRITICAL" => "critical",
        "ERROR" => "high",
        "WARNING" => "medium",
        _ => "",
    }
}

#[talos_module(world = "minimal-node")]
fn run(input: String) -> Result<String, String> {
    let env: Envelope = serde_json::from_str(&input).map_err(|e| e.to_string())?;

    let (incident, top_incident_id, top_state) = match env.data.or(env.input) {
        Some(d) => (d.incident.or(env.incident), d.incident_id, d.state),
        None => (env.incident, String::new(), String::new()),
    };
    let Some(inc) = incident else {
        return Ok(serde_json::json!({
            "normalized": 0,
            "skipped": 1,
            "reason": "no incident object in payload",
        })
        .to_string());
    };

    // Controller-extracted fields win (they tolerate id-as-number);
    // fall back to the incident body for direct-test payloads.
    let state = if top_state.is_empty() {
        inc.state.clone()
    } else {
        top_state
    };
    let incident_id = if top_incident_id.is_empty() {
        inc.incident_id.clone()
    } else {
        top_incident_id
    };

    if state == "closed" {
        let on_closed = if !env.config.on_closed.is_empty() {
            env.config.on_closed.as_str()
        } else if env.config.include_closed {
            "ingest" // legacy INCLUDE_CLOSED=true compatibility
        } else {
            "resolve"
        };
        match on_closed {
            "ignore" => {
                return Ok(serde_json::json!({
                    "normalized": 0,
                    "skipped": 1,
                    "reason": "state=closed (ON_CLOSED=ignore)",
                })
                .to_string());
            }
            "ingest" => {} // fall through to normal alert emission below
            _ => {
                // "resolve" (default): the incident closing means the
                // condition CLEARED — emit a recovery event keyed on the
                // SAME dedup identity the open event used, so the engine
                // resolves the rolling alert instead of bumping it.
                let resource = if !inc.resource_display_name.is_empty() {
                    inc.resource_display_name.clone()
                } else if !inc.resource_name.is_empty() {
                    inc.resource_name.clone()
                } else {
                    inc.scoping_project_id.clone()
                };
                let policy = if inc.policy_name.is_empty() {
                    inc.condition_name.clone()
                } else {
                    inc.policy_name.clone()
                };
                return Ok(serde_json::json!({
                    "normalized": 0,
                    "resolved": 1,
                    "state": "closed",
                    "__ops_alert__": { "alerts": [{
                        "source": format!("{}gcp-monitoring", env.config.source_prefix),
                        "dedup_key": format!("gcpmon|{}|{}", norm_key(&policy), norm_key(&resource)),
                        "status_event": "resolved",
                    }] },
                })
                .to_string());
            }
        }
    }

    let resource = if !inc.resource_display_name.is_empty() {
        inc.resource_display_name.clone()
    } else if !inc.resource_name.is_empty() {
        inc.resource_name.clone()
    } else {
        inc.scoping_project_id.clone()
    };
    let policy = if inc.policy_name.is_empty() {
        inc.condition_name.clone()
    } else {
        inc.policy_name.clone()
    };
    let title = if inc.summary.is_empty() {
        format!("[{}] {}", policy, resource)
    } else {
        inc.summary.clone()
    };

    let hint = severity_hint(&inc.severity);
    let mut alert = serde_json::json!({
        "source": format!("{}gcp-monitoring", env.config.source_prefix),
        "dedup_key": format!("gcpmon|{}|{}", norm_key(&policy), norm_key(&resource)),
        "title": title,
        "resource": resource,
        "raw": {
            "incident_id": incident_id.clone(),
            "state": state.clone(),
            "policy_name": inc.policy_name,
            "condition_name": inc.condition_name,
            "scoping_project_id": inc.scoping_project_id,
            "url": inc.url,
            "observed_value": inc.observed_value,
            "threshold_value": inc.threshold_value,
        },
    });
    if !incident_id.is_empty() {
        alert["external_id"] = serde_json::json!(incident_id);
    }
    if !inc.severity.is_empty() {
        alert["severity_raw"] = serde_json::json!(inc.severity);
    }
    if !hint.is_empty() {
        alert["severity_hint"] = serde_json::json!(hint);
    }

    Ok(serde_json::json!({
        "normalized": 1,
        "skipped": 0,
        "state": state,
        "__ops_alert__": { "alerts": [alert] },
    })
    .to_string())
}
