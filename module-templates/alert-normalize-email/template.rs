use talos_sdk_macros::talos_module;

// Normalize alert-bearing emails into ops-alerts (the `__ops_alert__`
// engine-hook envelope; see talos-workflow-engine-core reserved_keys).
//
// Input: the `Gmail: List Messages` output shape —
//   { "input": { "messages": [ { "id", "from", "subject", "date", "snippet" } ] } }
// (also accepted at the top level for direct testing).
//
// Recognized senders/shapes and their dedup identity:
//   * Snyk vulnerability digests   → source "snyk-email",
//     dedup on the org/project extracted from the subject (one rolling
//     alert per org that re-bumps per digest, not one per email).
//   * AWS Health / AWS Notifications → source "aws-health-email",
//     dedup on the event headline with volatile ids stripped.
//   * ServiceNow case assignments  → source "servicenow-email",
//     dedup on the case number (external_id).
//   * Optional generic alert mail  → source "generic-email" (config
//     INCLUDE_GENERIC), dedup on normalized subject.
//
// Severity here is a HEURISTIC HINT only (severity_hint applies on first
// ingest; the Smart-Classifier pass and human corrections own it after
// that). Everything is typed-struct parsed per the WASM fuel rules.

#[derive(serde::Deserialize)]
struct Envelope {
    #[serde(default)]
    input: Option<Batch>,
    #[serde(default)]
    messages: Option<Vec<Message>>,
}

#[derive(serde::Deserialize, Default)]
struct Batch {
    #[serde(default)]
    messages: Vec<Message>,
}

#[derive(serde::Deserialize, Clone)]
struct Message {
    #[serde(default)]
    id: String,
    #[serde(default)]
    from: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    date: String,
    #[serde(default)]
    snippet: String,
}

fn norm_key(s: &str) -> String {
    // Lowercase, collapse non-alphanumerics, and strip long digit runs
    // (timestamps/counters) so re-fired alerts about the same condition
    // dedup together instead of creating a row per email.
    let mut out = String::with_capacity(s.len());
    let mut digits = 0usize;
    let mut last_dash = false;
    for c in s.trim().to_lowercase().chars() {
        if c.is_ascii_digit() {
            digits += 1;
            continue;
        }
        if digits > 0 && digits <= 3 {
            // Short numbers are usually identity (e.g. "Node.js 20") — keep.
            out.push('#');
        }
        digits = 0;
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

struct Parsed {
    source: &'static str,
    dedup_key: String,
    title: String,
    resource: String,
    external_id: String,
    severity_hint: &'static str,
}

fn classify(m: &Message, include_generic: bool) -> Option<Parsed> {
    let from = m.from.to_lowercase();
    let subject = m.subject.trim();
    let subject_lc = subject.to_lowercase();
    let snippet_lc = m.snippet.to_lowercase();

    // ── Snyk vulnerability digests ──────────────────────────────────
    if from.contains("snyk") || subject_lc.contains("[snyk]") {
        // Subject shape: "[snyk] Vulnerability alert for the <org> organization"
        let org = subject
            .split("for the ")
            .nth(1)
            .map(|s| s.trim_end_matches(" organization").trim())
            .unwrap_or("unknown-org");
        let hint = if snippet_lc.contains("critical") {
            "critical"
        } else {
            "high"
        };
        return Some(Parsed {
            source: "snyk-email",
            dedup_key: format!("snyk|{}", norm_key(org)),
            title: subject.to_string(),
            resource: org.to_string(),
            external_id: String::new(),
            severity_hint: hint,
        });
    }

    // ── AWS Health / notifications ──────────────────────────────────
    // Sender-DOMAIN checks miss AWS mail relayed through a Google Group
    // ("'Amazon Web Services' via <group>" — the From domain is the
    // group's, not Amazon's; observed live 2026-07-17). Also match the
    // display NAME and the AWS Health envelope marker in the snippet.
    if from.contains("aws-marketing")
        || from.contains("amazonaws")
        || from.contains("aws.amazon")
        || from.contains("amazon web services")
        || snippet_lc.contains("aws health event")
    {
        let action_required =
            subject_lc.contains("action may be required") || subject_lc.contains("action required");
        // "[URGENT] [ACTION REQUIRED]" (e.g. imminent scheduled maintenance)
        // outranks a plain action-may-be-required notice.
        let urgent = subject_lc.contains("urgent");
        return Some(Parsed {
            source: "aws-health-email",
            dedup_key: format!("aws|{}", norm_key(subject)),
            title: subject.to_string(),
            resource: String::new(),
            external_id: String::new(),
            severity_hint: if urgent {
                "high"
            } else if action_required {
                "medium"
            } else {
                "info"
            },
        });
    }

    // ── ServiceNow case assignments ─────────────────────────────────
    if subject_lc.contains("has been assigned to group")
        || (from.contains("service") && snippet_lc.contains("case number"))
    {
        // "A new Case DS0019461 has been assigned to group WT Security Support"
        let case = subject
            .split_whitespace()
            .find(|w| {
                w.len() >= 6
                    && w.chars().take(2).all(|c| c.is_ascii_uppercase())
                    && w.chars().skip(2).all(|c| c.is_ascii_digit())
            })
            .unwrap_or("");
        let group = subject.split("group ").nth(1).unwrap_or("").trim();
        let priority_low =
            snippet_lc.contains("priority: 4") || snippet_lc.contains("priority: 5");
        return Some(Parsed {
            source: "servicenow-email",
            dedup_key: if case.is_empty() {
                format!("snow|{}", norm_key(subject))
            } else {
                format!("snow|{case}")
            },
            title: subject.to_string(),
            resource: group.to_string(),
            external_id: case.to_string(),
            severity_hint: if priority_low { "low" } else { "medium" },
        });
    }

    // ── Optional generic alert mail ─────────────────────────────────
    if include_generic
        && ["alert", "incident", "outage", "failure", "down", "degraded"]
            .iter()
            .any(|k| subject_lc.contains(k))
    {
        return Some(Parsed {
            source: "generic-email",
            dedup_key: format!("generic|{}", norm_key(subject)),
            title: subject.to_string(),
            resource: String::new(),
            external_id: String::new(),
            severity_hint: "",
        });
    }

    None
}

#[talos_module(world = "minimal-node")]
fn run(input: String) -> Result<String, String> {
    let env: Envelope = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let config: serde_json::Value = serde_json::from_str(&input)
        .ok()
        .and_then(|v: serde_json::Value| v.get("config").cloned())
        .unwrap_or(serde_json::json!({}));
    let source_prefix = config
        .get("SOURCE_PREFIX")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let include_generic = config
        .get("INCLUDE_GENERIC")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let messages = env
        .input
        .map(|b| b.messages)
        .or(env.messages)
        .unwrap_or_default();

    let mut alerts: Vec<serde_json::Value> = Vec::new();
    let mut skipped = 0usize;
    for m in &messages {
        match classify(m, include_generic) {
            Some(p) => {
                let mut alert = serde_json::json!({
                    "source": format!("{source_prefix}{}", p.source),
                    "dedup_key": p.dedup_key,
                    "title": p.title,
                    "raw": {
                        "message_id": m.id,
                        "from": m.from,
                        "date": m.date,
                        "snippet": m.snippet,
                    },
                });
                if !p.resource.is_empty() {
                    alert["resource"] = serde_json::json!(p.resource);
                }
                if !p.external_id.is_empty() {
                    alert["external_id"] = serde_json::json!(p.external_id);
                }
                if !p.severity_hint.is_empty() {
                    alert["severity_hint"] = serde_json::json!(p.severity_hint);
                }
                alerts.push(alert);
            }
            None => skipped += 1,
        }
    }

    // The engine's `__ops_alert__` hook persists `alerts`; the summary
    // fields are the node's user-visible output for downstream digests.
    Ok(serde_json::json!({
        "normalized": alerts.len(),
        "skipped_non_alert": skipped,
        "sources": alerts.iter()
            .filter_map(|a| a.get("source").and_then(|s| s.as_str()))
            .collect::<std::collections::BTreeSet<_>>(),
        "__ops_alert__": { "alerts": alerts },
    })
    .to_string())
}
