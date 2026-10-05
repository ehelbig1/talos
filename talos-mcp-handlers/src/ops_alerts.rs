//! Ops-alerts triage surface — the operator side of the alert-triage
//! pipeline (`ops_alerts` domain). Modules ingest through the
//! `__ops_alert__` output envelope; the one ingest door here is
//! `report_ops_alert` (2026-10-05), for an operator-side reporter (a host
//! script such as the backup drill, an agent) raising or resolving an
//! alert for the CALLING user. It applies the envelope's own per-entry
//! rules — `talos_ops_alerts_repository::envelope::apply_entry`: the
//! reserved `talos` namespace refused, DLP before persistence, bounded
//! `raw` — so the two doors cannot disagree about an entry.
//!
//! Thin handlers per the architectural mandate: parse/validate →
//! `talos_ops_alerts_repository::OpsAlertRepository` → format. The one
//! semantically-loaded tool is `correct_ops_alert_severity`: human
//! corrections are the distillation gold set (they outrank classifier
//! labels and survive dedup bumps), mirroring the inbox-organizer
//! correction→few-shot loop.

use super::types::JsonRpcResponse;
use super::utils::{mcp_denied, mcp_error, mcp_text};
use super::{auth, McpState};
use std::sync::Arc;
use talos_ops_alerts_repository::envelope::{apply_entry, EntryOutcome, EntryRefusal};
use talos_ops_alerts_repository::{
    IngestOutcome, OpsAlertFilter, OpsAlertIngestError, OpsAlertRepository, ASSIGNABLE_SEVERITIES,
};
use uuid::Uuid;

pub fn tool_schemas() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "name": "list_ops_alerts",
            "description": "List normalized operational alerts (Snyk/AWS-Health/ServiceNow email alerts, GCP Monitoring, webhooks) ingested via the __ops_alert__ pipeline. Defaults to active (non-resolved) alerts, newest activity first.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "status": { "type": "string", "enum": ["new", "acked", "resolved", "all"], "description": "Filter by lifecycle status. Omitted = ACTIVE only (new + acked — the documented default); 'all' includes resolved." },
                    "severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info", "noise", "unclassified"], "description": "Filter by triaged severity" },
                    "source": { "type": "string", "description": "Filter by source label (e.g. 'snyk-email')" },
                    "since_hours": { "type": "number", "description": "Only alerts with activity in the last N hours (max 720)" },
                    "limit": { "type": "number", "description": "Max rows (default 50, max 200)" }
                }
            }
        }),
        serde_json::json!({
            "name": "set_ops_alert_status",
            "description": "Advance an ops-alert through its lifecycle: 'acked' (only from new) or 'resolved' (from new/acked). A re-fired resolved alert automatically reopens to new.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "alert_id": { "type": "string", "description": "UUID of the alert" },
                    "status": { "type": "string", "enum": ["acked", "resolved"] }
                },
                "required": ["alert_id", "status"]
            }
        }),
        serde_json::json!({
            "name": "correct_ops_alert_severity",
            "description": "Record a HUMAN severity correction on an ops-alert. Corrections are the triage gold signal: they overwrite classifier labels, are never overwritten by future classifier runs, and survive dedup bumps — they feed the classifier's few-shot/distillation loop.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "alert_id": { "type": "string", "description": "UUID of the alert" },
                    "severity": { "type": "string", "enum": ["critical", "high", "medium", "low", "info", "noise"] }
                },
                "required": ["alert_id", "severity"]
            }
        }),
        serde_json::json!({
            "name": "get_ops_alerts_digest",
            "description": "Rollup of the active ops-alert set: counts by severity and source, new-in-last-24h, and reopened (re-fired after resolve) counts. Feed for the morning dispatch.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        serde_json::json!({
            "name": "report_ops_alert",
            "description": "Raise or resolve an ops-alert for YOU (the calling user) — for an operator-side reporter such as a host script or an agent. Raising creates the alert, or bumps it when an alert with the same dedup_key exists (reopening it if it was resolved). Pass status_event: 'resolved' to resolve the active alert with that dedup_key. Same rules as the __ops_alert__ module envelope: the 'talos' source and 'talos/' dedup keys are reserved for the platform and refused; title, resource, external_id and raw are DLP-redacted before they are stored; an oversized raw is dropped. Returns what happened (created / bumped / reopened / resolved / no_active_alert); raw is never echoed.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source": { "type": "string", "description": "Who raised it (e.g. 'backup-drill'). 'talos' is reserved." },
                    "dedup_key": { "type": "string", "description": "Identity of the condition: a repeat bumps one alert, and a resolve names it. Keys starting 'talos/' are reserved." },
                    "title": { "type": "string", "description": "One-line summary. Required unless resolving." },
                    "severity_hint": { "type": "string", "enum": ["critical", "high", "medium", "low", "info"], "description": "Initial severity for a NEW alert (ignored on a bump). Omitted = unclassified." },
                    "resource": { "type": "string", "description": "What the alert is about (a host, a service, a backup copy)." },
                    "external_id": { "type": "string", "description": "The reporter's own id for this occurrence, if any." },
                    "raw": { "type": "object", "description": "Structured detail stored with the alert (DLP-redacted, dropped above 64 KiB). Never echoed back." },
                    "status_event": { "type": "string", "enum": ["resolved"], "description": "'resolved' resolves the active alert with this dedup_key instead of raising. Any other value is refused." }
                },
                "required": ["source", "dedup_key"]
            }
        }),
        serde_json::json!({
            "name": "cleanup_ops_alerts",
            "description": "Delete RESOLVED ops-alerts older than a threshold (housekeeping; active alerts are never touched).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "older_than_days": { "type": "number", "description": "Delete resolved alerts older than this many days (default 30, min 7)" }
                }
            }
        }),
    ]
}

pub async fn dispatch(
    name: &str,
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    match name {
        "list_ops_alerts" => Some(handle_list(req_id, args, state, user_id).await),
        "set_ops_alert_status" => Some(handle_set_status(req_id, args, state, user_id).await),
        "correct_ops_alert_severity" => Some(handle_correct(req_id, args, state, user_id).await),
        "get_ops_alerts_digest" => Some(handle_digest(req_id, state, user_id).await),
        "cleanup_ops_alerts" => Some(handle_cleanup(req_id, args, state, user_id).await),
        // A WRITE attributed to the caller: the bare `agent.user_id`, never
        // the nil default above (a nil user is not "no tenant").
        "report_ops_alert" => Some(handle_report(req_id, args, state, agent.user_id).await),
        _ => None,
    }
}

fn repo(state: &McpState) -> OpsAlertRepository {
    OpsAlertRepository::new(state.db_pool.clone())
}

fn parse_alert_id(
    args: &serde_json::Value,
    req_id: &Option<serde_json::Value>,
) -> Result<Uuid, JsonRpcResponse> {
    args.get("alert_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            mcp_error(
                req_id.clone(),
                -32602,
                "Missing or invalid required field: alert_id (UUID)",
            )
        })
}

async fn handle_list(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let limit = match crate::utils::validate_range_i64(args, "limit", 1, 200, 50, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let since_hours =
        match crate::utils::validate_range_i64(args, "since_hours", 1, 720, 720, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    // `since` only constrains when the caller supplied it explicitly.
    let since = args
        .get("since_hours")
        .is_some()
        .then(|| chrono::Utc::now() - chrono::Duration::hours(since_hours));
    let opt_str = |k: &str| {
        args.get(k)
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    // Omitted status = active-only (the tool description has always
    // promised this; pre-fix the repo returned ALL statuses — the
    // description/behavior mismatch from the 2026-07-18 retrospective).
    // 'all' is the explicit escape hatch.
    let status_arg = opt_str("status");
    let (status, exclude_resolved) = match status_arg.as_deref() {
        None => (None, true),
        Some("all") => (None, false),
        Some(_) => (status_arg.clone(), false),
    };
    let filter = OpsAlertFilter {
        status,
        exclude_resolved,
        severity: opt_str("severity"),
        source: opt_str("source"),
        since,
        limit: Some(limit),
    };
    match repo(state).list(user_id, filter).await {
        Ok(rows) => {
            let alerts: Vec<serde_json::Value> = rows
                .iter()
                .map(|a| {
                    serde_json::json!({
                        "id": a.id,
                        "source": a.source,
                        "external_id": a.external_id,
                        "title": a.title,
                        "resource": a.resource,
                        "severity": a.severity,
                        "severity_raw": a.severity_raw,
                        "triage_source": a.triage_source,
                        "triage_confidence": a.triage_confidence,
                        "corrected": a.corrected_severity.is_some(),
                        "status": a.status,
                        "occurrence_count": a.occurrence_count,
                        "first_seen": a.first_seen.to_rfc3339(),
                        "last_seen": a.last_seen.to_rfc3339(),
                        "reopened_at": a.reopened_at.map(|t| t.to_rfc3339()),
                        "resolved_source": a.resolved_source,
                    })
                })
                .collect();
            mcp_text(
                req_id,
                &serde_json::json!({ "count": alerts.len(), "alerts": alerts }).to_string(),
            )
        }
        Err(e) => {
            tracing::error!("list_ops_alerts failed: {:#}", e);
            crate::utils::database_error(req_id)
        }
    }
}

async fn handle_set_status(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let alert_id = match parse_alert_id(args, &req_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let status = args.get("status").and_then(|v| v.as_str()).unwrap_or("");
    let result = match status {
        "acked" => repo(state).ack(user_id, alert_id).await,
        "resolved" => repo(state).resolve(user_id, alert_id).await,
        other => {
            return mcp_error(
                req_id,
                -32602,
                &format!("Invalid status '{other}' — expected 'acked' or 'resolved'"),
            )
        }
    };
    match result {
        Ok(true) => mcp_text(
            req_id,
            &serde_json::json!({ "alert_id": alert_id, "status": status }).to_string(),
        ),
        Ok(false) => mcp_denied(
            req_id,
            -32000,
            "Alert not found, not yours, or not in a state that allows this transition \
             (acked requires 'new'; resolved requires 'new' or 'acked')",
        ),
        Err(e) => {
            tracing::error!("set_ops_alert_status failed: {:#}", e);
            crate::utils::database_error(req_id)
        }
    }
}

async fn handle_correct(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let alert_id = match parse_alert_id(args, &req_id) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let severity = args.get("severity").and_then(|v| v.as_str()).unwrap_or("");
    if talos_ops_alerts_repository::validate_severity(severity).is_err() {
        return mcp_error(
            req_id,
            -32602,
            &format!("Invalid severity '{severity}' — expected one of {ASSIGNABLE_SEVERITIES:?}"),
        );
    }
    match repo(state)
        .correct_severity(user_id, alert_id, severity)
        .await
    {
        Ok(Some(bridge)) => {
            // Fan the human label into any ML dataset already tracking this
            // alert (corrections→distillation bridge). Fire-and-forget: a
            // bridge failure must never fail the correction the operator just
            // made.
            talos_ml::spawn_ops_correction_bridge(
                user_id,
                bridge.example_key,
                bridge.features_text,
                severity.to_string(),
            );
            mcp_text(
                req_id,
                &serde_json::json!({
                    "alert_id": alert_id,
                    "severity": severity,
                    "corrected": true,
                    "note": "Correction recorded — outranks classifier labels and survives dedup bumps."
                })
                .to_string(),
            )
        }
        Ok(None) => mcp_denied(req_id, -32000, "Alert not found or not yours"),
        Err(e) => {
            tracing::error!("correct_ops_alert_severity failed: {:#}", e);
            crate::utils::database_error(req_id)
        }
    }
}

async fn handle_digest(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    match repo(state).digest(user_id).await {
        Ok(d) => mcp_text(
            req_id,
            &serde_json::json!({
                "active_by_severity": d.active_by_severity
                    .iter().map(|(s, n)| serde_json::json!({"severity": s, "count": n})).collect::<Vec<_>>(),
                "active_by_source": d.active_by_source
                    .iter().map(|(s, n)| serde_json::json!({"source": s, "count": n})).collect::<Vec<_>>(),
                "new_last_24h": d.new_last_24h,
                "reopened_active": d.reopened_active,
            })
            .to_string(),
        ),
        Err(e) => {
            tracing::error!("get_ops_alerts_digest failed: {:#}", e);
            crate::utils::database_error(req_id)
        }
    }
}

/// The severities a reporter may suggest for a new alert. `noise` is a
/// triage verdict, not something a source reports about itself.
const REPORTABLE_SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "info"];

/// A validated `report_ops_alert` call: the entry to apply, built from the
/// declared arguments only (nothing else the caller sent reaches the store).
#[derive(Debug, PartialEq)]
struct ReportArgs {
    entry: serde_json::Value,
    resolving: bool,
}

/// Parse + validate `report_ops_alert`'s arguments. Pure. The reserved
/// namespace is NOT checked here — `apply_entry` is its one gate, shared
/// with the module envelope.
fn parse_report_args(args: &serde_json::Value) -> Result<ReportArgs, String> {
    // Absent → None; present but not a string → refused (a mistyped field
    // must not be read as absent and silently change what is written).
    let opt_str = |k: &str| -> Result<Option<String>, String> {
        match args.get(k) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::String(s)) => {
                let t = s.trim();
                Ok((!t.is_empty()).then(|| t.to_string()))
            }
            Some(_) => Err(format!("'{k}' must be a string")),
        }
    };
    let required = |k: &str| -> Result<String, String> {
        opt_str(k)?.ok_or_else(|| format!("Missing required field: {k}"))
    };

    let source = required("source")?;
    let dedup_key = required("dedup_key")?;
    let resolving = match opt_str("status_event")? {
        None => false,
        Some(s) if s == "resolved" => true,
        Some(other) => {
            return Err(format!(
                "Invalid status_event '{other}' — only 'resolved' is accepted"
            ))
        }
    };

    let mut entry = serde_json::Map::new();
    entry.insert("source".into(), source.into());
    entry.insert("dedup_key".into(), dedup_key.into());
    if resolving {
        entry.insert("status_event".into(), "resolved".into());
        return Ok(ReportArgs {
            entry: entry.into(),
            resolving,
        });
    }

    entry.insert("title".into(), required("title")?.into());
    if let Some(sev) = opt_str("severity_hint")? {
        if !REPORTABLE_SEVERITIES.contains(&sev.as_str()) {
            return Err(format!(
                "Invalid severity_hint '{sev}' — expected one of {REPORTABLE_SEVERITIES:?}"
            ));
        }
        entry.insert("severity_hint".into(), sev.into());
    }
    for k in ["resource", "external_id"] {
        if let Some(v) = opt_str(k)? {
            entry.insert(k.into(), v.into());
        }
    }
    match args.get("raw") {
        None | Some(serde_json::Value::Null) => {}
        Some(raw @ serde_json::Value::Object(_)) => {
            entry.insert("raw".into(), raw.clone());
        }
        Some(_) => return Err("'raw' must be an object".into()),
    }
    Ok(ReportArgs {
        entry: entry.into(),
        resolving,
    })
}

/// The response body for an applied entry. Says what happened and names
/// the row; never carries `raw` or any other field the caller sent.
fn report_outcome_json(outcome: &EntryOutcome) -> serde_json::Value {
    match outcome {
        EntryOutcome::Ingested(IngestOutcome::Created { id }) => {
            serde_json::json!({ "result": "created", "alert_id": id, "occurrence_count": 1 })
        }
        EntryOutcome::Ingested(IngestOutcome::Bumped {
            id,
            occurrence_count,
            reopened,
        }) => serde_json::json!({
            "result": if *reopened { "reopened" } else { "bumped" },
            "alert_id": id,
            "occurrence_count": occurrence_count,
        }),
        EntryOutcome::Resolved => serde_json::json!({ "result": "resolved" }),
        EntryOutcome::NoActiveAlert => serde_json::json!({ "result": "no_active_alert" }),
    }
}

/// `report_ops_alert`: parse → resolve the caller's org → apply the entry
/// through the envelope's own rules → format.
async fn handle_report(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Option<Uuid>,
) -> JsonRpcResponse {
    // Every route that reaches here resolves a user (the authenticated
    // middleware refuses an unbound agent; `/mcp/local` resolves its dev
    // user). Refused rather than attributed to a nil user if that changes.
    let Some(user_id) = user_id else {
        return mcp_denied(req_id, -32001, "Unauthorized: agent is not bound to a user");
    };
    let parsed = match parse_report_args(args) {
        Ok(p) => p,
        Err(msg) => return mcp_error(req_id, -32602, &msg),
    };
    // `org_id` is stamped on CREATE only and nothing reads it yet
    // (`ops_alerts` is user-scoped, no RLS). With no actor to take it from,
    // stamp the caller's PERSONAL org — what the `set_org_id_from_personal_org`
    // trigger stamps on the user-scoped tables that have it. A resolve
    // writes no org, so it does not read one. An unreadable org REFUSES
    // rather than writing NULL in its place.
    let org_id = if parsed.resolving {
        None
    } else {
        match state.secrets_manager.resolve_personal_org_id(user_id).await {
            Ok(org) => org,
            Err(e) => {
                tracing::error!("report_ops_alert: personal org lookup failed: {:#}", e);
                return crate::utils::database_error(req_id);
            }
        }
    };
    match apply_entry(&repo(state), user_id, org_id, &parsed.entry).await {
        Ok(outcome) => mcp_text(req_id, &report_outcome_json(&outcome).to_string()),
        Err(refusal @ EntryRefusal::ReservedNamespace { .. }) => {
            mcp_denied(req_id, -32602, &refusal.to_string())
        }
        Err(refusal @ EntryRefusal::UnknownStatusEvent { .. }) => {
            mcp_error(req_id, -32602, &refusal.to_string())
        }
        // Validation text names the empty field only ("empty title").
        Err(EntryRefusal::Ingest(e @ OpsAlertIngestError::Validation(_))) => {
            mcp_error(req_id, -32602, &e.to_string())
        }
        Err(e) => {
            tracing::error!("report_ops_alert failed: {:#}", e);
            crate::utils::database_error(req_id)
        }
    }
}

async fn handle_cleanup(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // Min 7 mirrors cleanup_old_alerts: a small-but-positive floor so a
    // typo can't purge yesterday's audit trail (MCP-997 class).
    let days = match crate::utils::validate_range_i64(args, "older_than_days", 7, 3650, 30, &req_id)
    {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };
    match repo(state).delete_resolved_older_than(user_id, days).await {
        Ok(n) => mcp_text(
            req_id,
            &serde_json::json!({ "deleted": n, "older_than_days": days }).to_string(),
        ),
        Err(e) => {
            tracing::error!("cleanup_ops_alerts failed: {:#}", e);
            crate::utils::database_error(req_id)
        }
    }
}

#[cfg(test)]
mod report_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_raise_keeps_only_the_declared_fields() {
        let p = parse_report_args(&json!({
            "source": " backup-drill ",
            "dedup_key": "backup-drill|artifact",
            "title": "Backup drill failed at [4/8] restore postgres",
            "severity_hint": "high",
            "resource": "artifact",
            "raw": {"step": "4/8"},
            "severity_raw": "smuggled",
            "status": "resolved",
        }))
        .expect("valid raise");
        assert!(!p.resolving);
        assert_eq!(
            p.entry,
            json!({
                "source": "backup-drill",
                "dedup_key": "backup-drill|artifact",
                "title": "Backup drill failed at [4/8] restore postgres",
                "severity_hint": "high",
                "resource": "artifact",
                "raw": {"step": "4/8"},
            })
        );
    }

    #[test]
    fn a_resolve_needs_no_title_and_carries_only_its_identity() {
        let p = parse_report_args(&json!({
            "source": "backup-drill",
            "dedup_key": "backup-drill|artifact",
            "status_event": "resolved",
            "raw": {"ignored": true},
        }))
        .expect("valid resolve");
        assert!(p.resolving);
        assert_eq!(
            p.entry,
            json!({"source": "backup-drill", "dedup_key": "backup-drill|artifact",
                   "status_event": "resolved"})
        );
    }

    #[test]
    fn invalid_arguments_are_refused_with_the_field_named() {
        let base = json!({"source": "s", "dedup_key": "k", "title": "t"});
        let with = |k: &str, v: serde_json::Value| {
            let mut a = base.clone();
            a[k] = v;
            a
        };
        let without = |k: &str| {
            let mut a = base.clone();
            a.as_object_mut().unwrap().remove(k);
            a
        };
        for (args, needle) in [
            (without("source"), "source"),
            (without("dedup_key"), "dedup_key"),
            (without("title"), "title"),
            (with("title", json!("   ")), "title"),
            (with("source", json!(7)), "source"),
            (with("status_event", json!("closed")), "status_event"),
            (with("status_event", json!("open")), "status_event"),
            (with("status_event", json!(true)), "status_event"),
            (with("severity_hint", json!("noise")), "severity_hint"),
            (with("severity_hint", json!("sev1")), "severity_hint"),
            (with("raw", json!("text")), "raw"),
            (with("raw", json!([1, 2])), "raw"),
            (with("resource", json!({"a": 1})), "resource"),
        ] {
            let err = parse_report_args(&args).expect_err(&args.to_string());
            assert!(err.contains(needle), "{args}: {err}");
        }
        // A resolve still needs its identity.
        let err = parse_report_args(&json!({"source": "s", "status_event": "resolved"}))
            .expect_err("no dedup_key");
        assert!(err.contains("dedup_key"), "{err}");
    }

    #[test]
    fn the_reserved_namespace_is_left_to_the_shared_gate() {
        // Parsing accepts it, so the ONE refusal is the envelope's own
        // `apply_entry` (covered there and by the DB test). A second check
        // here would be a second rule that can drift from the first.
        assert!(
            parse_report_args(&json!({"source": "talos", "dedup_key": "k", "title": "t"})).is_ok()
        );
        assert!(parse_report_args(
            &json!({"source": "s", "dedup_key": "talos/wf/x", "status_event": "resolved"})
        )
        .is_ok());
    }

    #[test]
    fn outcomes_say_what_happened_and_never_echo_raw() {
        let id = Uuid::new_v4();
        for (outcome, expected) in [
            (
                EntryOutcome::Ingested(IngestOutcome::Created { id }),
                "created",
            ),
            (
                EntryOutcome::Ingested(IngestOutcome::Bumped {
                    id,
                    occurrence_count: 3,
                    reopened: false,
                }),
                "bumped",
            ),
            (
                EntryOutcome::Ingested(IngestOutcome::Bumped {
                    id,
                    occurrence_count: 4,
                    reopened: true,
                }),
                "reopened",
            ),
            (EntryOutcome::Resolved, "resolved"),
            (EntryOutcome::NoActiveAlert, "no_active_alert"),
        ] {
            let body = report_outcome_json(&outcome);
            assert_eq!(body["result"], expected);
            let keys: Vec<&String> = body.as_object().unwrap().keys().collect();
            assert!(
                keys.iter()
                    .all(|k| ["result", "alert_id", "occurrence_count"].contains(&k.as_str())),
                "{body}"
            );
        }
    }
}
