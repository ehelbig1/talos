//! `__ops_alert__` envelope ingestion — the shared core behind every
//! surface that accepts the opt-in output key.
//!
//! Extracted from `talos-engine`'s `ControllerNodeHook` (P2, 2026-07-17)
//! so the SAME parse → cap → DLP → tenancy → ingest path serves:
//!
//!   * engine node-completion + pipeline-step hooks (workflow executions),
//!   * `ModuleExecutionService::complete_execution_from_worker` — the
//!     completion chokepoint every module-bound push dispatch funnels
//!     through (GCP Monitoring Pub/Sub, Gmail/GCal watches, inbound
//!     webhooks, the `talos.results.*` fire-and-forget subscriber).
//!
//! Keeping the whole protocol in the domain crate mirrors `talos-memory`
//! (domain crate owns service semantics, not just SQL) and guarantees a
//! future consumer can't fork the DLP/tenancy discipline.
//!
//! Security invariants (unchanged from the hook implementation):
//!   * Every free-text field is DLP-redacted BEFORE persistence —
//!     `ops_alerts` stores plaintext, and the envelope is WASM-supplied
//!     (MCP-989/990 posture applied to the PERSISTED values).
//!   * Tenancy comes from the execution's bound actor
//!     (`actors.user_id`/`org_id`) — never from the envelope itself.
//!   * Per-output volume cap with LOGGED overflow (no silent caps).
//!   * Failures count against `ops_alert_ingest_failures_total{reason}`.

use serde_json::Value as JsonValue;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

/// Bound on alerts a single output may ingest. Far above any legitimate
/// parser batch (an email poll yields ≤ ~20) while keeping a hostile
/// module from flooding the store in one shot.
pub const MAX_OPS_ALERTS_PER_OUTPUT: usize = 50;

/// Pure extraction of the alert list from an output value. Returns
/// `None` when the reserved key is absent or the envelope is malformed
/// (neither an `alerts` array nor a single alert object carrying a
/// `dedup_key`). Does NOT apply the volume cap — the caller does, so it
/// can log the dropped count.
#[must_use]
pub fn extract_alerts(output: &JsonValue) -> Option<Vec<JsonValue>> {
    let oa = output.get(talos_workflow_engine_core::reserved_keys::OPS_ALERT)?;
    // `{"alerts": [...]}` (canonical) or a bare single-alert object.
    match oa.get("alerts").and_then(JsonValue::as_array) {
        Some(arr) => Some(arr.clone()),
        None if oa.get("dedup_key").is_some() => Some(vec![oa.clone()]),
        None => {
            tracing::warn!(
                "__ops_alert__ envelope present but neither an `alerts` array nor a \
                 single alert object (missing `dedup_key`) — ingest skipped"
            );
            None
        }
    }
}

/// Cheap presence probe so callers on hot paths can gate the (clone +
/// spawn) work without parsing the envelope.
#[must_use]
pub fn output_has_envelope(output: &JsonValue) -> bool {
    output
        .get(talos_workflow_engine_core::reserved_keys::OPS_ALERT)
        .is_some()
}

fn bump_failure_metric(reason: &str) {
    if let Some(m) = talos_metrics::global() {
        m.ops_alert_ingest_failures_total
            .with_label_values(&[reason])
            .inc();
    }
}

/// Parse the `__ops_alert__` envelope out of `output` and spawn the
/// batch ingest. Best-effort, fire-on-completion semantics: the caller's
/// latency is bounded by the parse + clone; the tenancy lookup and DB
/// writes run on a spawned task.
///
/// `context` labels the emitting surface in logs (`"engine_node"`,
/// `"pipeline_step"`, `"module_result"`) so an operator can tell which
/// dispatch family produced an ingest or a failure.
pub fn spawn_ingest_from_output(
    pool: Pool<Postgres>,
    actor_id: Option<Uuid>,
    output: &JsonValue,
    context: &'static str,
) {
    let Some(alerts) = extract_alerts(output) else {
        return;
    };
    if alerts.is_empty() {
        return;
    }
    let dropped = alerts.len().saturating_sub(MAX_OPS_ALERTS_PER_OUTPUT);
    if dropped > 0 {
        tracing::warn!(
            dropped,
            cap = MAX_OPS_ALERTS_PER_OUTPUT,
            context,
            "__ops_alert__ envelope exceeded the per-output cap — excess alerts dropped"
        );
    }
    let Some(actor_id) = actor_id else {
        tracing::warn!(
            count = alerts.len(),
            context,
            "__ops_alert__ envelope emitted but no actor is bound to this execution — \
             alerts dropped. Bind an actor to the workflow/watch (default-actor \
             resolution covers push dispatches unless it failed)."
        );
        bump_failure_metric("tenancy");
        return;
    };

    tokio::spawn(async move {
        // Tenancy from the bound actor — one lookup for the whole batch.
        let tenancy = talos_actor_repository::ActorRepository::new(pool.clone())
            .get_actor_tenancy(actor_id)
            .await;
        let (user_id, org_id) = match tenancy {
            Ok(Some(pair)) => pair,
            Ok(None) => {
                tracing::warn!(%actor_id, context, "__ops_alert__: bound actor not found — alerts dropped");
                bump_failure_metric("tenancy");
                return;
            }
            Err(e) => {
                tracing::warn!(%actor_id, context, error = %e, "__ops_alert__: tenancy lookup failed — alerts dropped");
                bump_failure_metric("tenancy");
                return;
            }
        };

        let repo = crate::OpsAlertRepository::new(pool);
        for a in alerts.into_iter().take(MAX_OPS_ALERTS_PER_OUTPUT) {
            let get = |k: &str| a.get(k).and_then(JsonValue::as_str).map(str::to_string);
            // DLP-redact BEFORE persistence (stored plaintext; see module doc).
            let redacted = |k: &str| get(k).map(|s| talos_dlp_provider::redact_str(&s));
            let alert = crate::NewOpsAlert {
                source: redacted("source").unwrap_or_default(),
                external_id: redacted("external_id"),
                dedup_key: get("dedup_key").unwrap_or_default(),
                title: redacted("title").unwrap_or_default(),
                resource: redacted("resource"),
                severity_raw: get("severity_raw"),
                severity_hint: get("severity_hint"),
                // `redact_json_bounded` returns None for oversized
                // payloads — the repository additionally bounds bytes.
                raw: a
                    .get("raw")
                    .and_then(talos_dlp_provider::redact_json_bounded),
            };
            match repo.ingest(user_id, org_id, alert).await {
                Ok(outcome) => {
                    tracing::debug!(%actor_id, context, ?outcome, "__ops_alert__ ingested");
                }
                Err(e) => {
                    let reason = e.metric_label();
                    bump_failure_metric(reason);
                    tracing::warn!(%actor_id, context, error = %e, reason, "__ops_alert__ ingest failed");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_canonical_alerts_array() {
        let out = json!({
            "normalized": 2,
            "__ops_alert__": { "alerts": [
                {"dedup_key": "a", "source": "s", "title": "t"},
                {"dedup_key": "b", "source": "s", "title": "u"},
            ]}
        });
        let alerts = extract_alerts(&out).expect("array envelope");
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn extract_bare_single_alert_object() {
        let out = json!({
            "__ops_alert__": {"dedup_key": "solo", "source": "gcp-monitoring", "title": "t"}
        });
        let alerts = extract_alerts(&out).expect("single-alert envelope");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0]["dedup_key"], "solo");
    }

    #[test]
    fn extract_rejects_malformed_envelope() {
        // Present but neither shape — skipped, not panicked.
        let out = json!({ "__ops_alert__": {"unexpected": true} });
        assert!(extract_alerts(&out).is_none());
        // Absent key.
        assert!(extract_alerts(&json!({"ok": 1})).is_none());
        // Non-object envelope.
        assert!(extract_alerts(&json!({"__ops_alert__": "nope"})).is_none());
    }

    #[test]
    fn presence_probe_matches_extraction_gate() {
        assert!(output_has_envelope(
            &json!({"__ops_alert__": {"alerts": []}})
        ));
        assert!(!output_has_envelope(&json!({"anything": "else"})));
    }
}
