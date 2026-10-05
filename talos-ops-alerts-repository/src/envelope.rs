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
//!     webhooks, the `talos.results.*` fire-and-forget subscriber),
//!   * the MCP `report_ops_alert` tool (2026-10-05) — an operator-side
//!     reporter (a host script, an agent) raising or resolving an alert
//!     for the calling user.
//!
//! Every surface applies ONE entry through [`apply_entry`]: classify
//! (reserved-namespace refusal, `status_event` routing) → DLP-redact
//! ([`redacted_alert`]) → ingest or resolve. A surface owns only how it
//! finds the tenant and what it does with the outcome; it cannot apply a
//! different rule to an entry.
//!
//! Keeping the whole protocol in the domain crate mirrors `talos-memory`
//! (domain crate owns service semantics, not just SQL) and guarantees a
//! future consumer can't fork the DLP/tenancy discipline.
//!
//! Envelope entry shapes:
//!   * ingest (default): `{source, dedup_key, title, ...}` — create/bump.
//!   * recovery: `{dedup_key, status_event: "resolved", ...}` — the
//!     source reported the condition cleared; resolves the rolling
//!     alert (`resolved_source = 'signal'`) instead of bumping it.
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

/// What one envelope entry asks the pipeline to do. Pure classification
/// — split from the ingest loop so the `status_event` contract is
/// unit-testable without Postgres (house testing convention).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryAction {
    /// Create-or-bump the rolling alert (the default entry shape).
    Ingest,
    /// Source-signaled recovery: resolve the alert with this dedup key.
    Resolve { dedup_key: String },
    /// `status_event` present but not a recognized value — skip the
    /// entry (fail-safe: a typo must not turn a recovery into a bump).
    SkipUnknownStatusEvent { status_event: String },
    /// Entry claims the platform-reserved namespace (`talos/` dedup
    /// keys or the `talos` source) — skip it. Modules process
    /// untrusted content and must not be able to bump, retitle, or
    /// resolve the self-monitoring bridge's alerts
    /// ([`crate::self_monitor`]).
    SkipReservedNamespace { dedup_key: String },
}

/// Classify one envelope entry. Only `status_event: "resolved"` is
/// recognized today; absence means ingest.
#[must_use]
pub fn classify_entry(entry: &JsonValue) -> EntryAction {
    // Reserved-namespace guard BEFORE any routing: `talos/…` dedup keys
    // and the `talos` source belong to the self-monitoring bridge, and
    // this boundary is the only line between sandboxed modules and the
    // platform's own alert rows (the ingest upsert and the per-key
    // resolve are deliberately namespace-agnostic for trusted callers).
    let dedup_key = entry
        .get("dedup_key")
        .and_then(JsonValue::as_str)
        .unwrap_or_default();
    let source = entry
        .get("source")
        .and_then(JsonValue::as_str)
        .unwrap_or_default();
    if dedup_key.starts_with(crate::self_monitor::RESERVED_DEDUP_PREFIX)
        || source == crate::self_monitor::SELF_ALERT_SOURCE
    {
        return EntryAction::SkipReservedNamespace {
            dedup_key: dedup_key.to_string(),
        };
    }
    match entry.get("status_event").and_then(JsonValue::as_str) {
        None => EntryAction::Ingest,
        Some("resolved") => EntryAction::Resolve {
            dedup_key: entry
                .get("dedup_key")
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string(),
        },
        Some(other) => EntryAction::SkipUnknownStatusEvent {
            status_event: other.to_string(),
        },
    }
}

fn bump_failure_metric(reason: &str) {
    if let Some(m) = talos_metrics::global() {
        m.ops_alert_ingest_failures_total
            .with_label_values(&[reason])
            .inc();
    }
}

/// What [`apply_entry`] did with one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryOutcome {
    /// Create-or-bump landed (created / bumped / reopened — see
    /// [`crate::IngestOutcome`]).
    Ingested(crate::IngestOutcome),
    /// A `status_event: "resolved"` entry moved an active alert to
    /// `resolved` (`resolved_source = 'signal'`).
    Resolved,
    /// A resolve entry matched no active alert — never seen, or already
    /// resolved. A normal no-op, not an error.
    NoActiveAlert,
}

/// Why [`apply_entry`] did not apply an entry.
#[derive(Debug, thiserror::Error)]
pub enum EntryRefusal {
    /// The entry claims the platform-reserved namespace (see
    /// [`EntryAction::SkipReservedNamespace`]). Nothing was written.
    #[error(
        "source '{}' and dedup keys starting '{}' are reserved for the platform's own alerts",
        crate::self_monitor::SELF_ALERT_SOURCE,
        crate::self_monitor::RESERVED_DEDUP_PREFIX
    )]
    ReservedNamespace { dedup_key: String },
    /// `status_event` was present but not `"resolved"`. Nothing was
    /// written: a typo must not turn a recovery into a bump.
    #[error("unknown status_event '{status_event}' (only \"resolved\" is recognised)")]
    UnknownStatusEvent { status_event: String },
    /// The create-or-bump was refused (validation) or failed (db).
    #[error(transparent)]
    Ingest(crate::OpsAlertIngestError),
    /// The resolve write failed.
    #[error("ops-alert resolve failed")]
    Resolve(#[source] anyhow::Error),
}

impl EntryRefusal {
    /// The `ops_alert_ingest_failures_total{reason}` label this refusal
    /// counts under, or `None` for one that is not counted (an unknown
    /// `status_event` never was).
    #[must_use]
    pub fn metric_label(&self) -> Option<&'static str> {
        match self {
            Self::ReservedNamespace { .. } => Some("namespace"),
            Self::UnknownStatusEvent { .. } => None,
            Self::Ingest(e) => Some(e.metric_label()),
            Self::Resolve(_) => Some("db"),
        }
    }
}

/// The [`crate::NewOpsAlert`] an ingest entry describes, with every
/// free-text field DLP-redacted. `ops_alerts` stores plaintext, so this
/// runs BEFORE persistence on every surface. `dedup_key` is NOT redacted:
/// it is an identity, and a redacted key would stop matching its own
/// resolve signal. Pure.
#[must_use]
pub fn redacted_alert(entry: &JsonValue) -> crate::NewOpsAlert {
    let get = |k: &str| entry.get(k).and_then(JsonValue::as_str).map(str::to_string);
    let redacted = |k: &str| get(k).map(|s| talos_dlp_provider::redact_str(&s));
    crate::NewOpsAlert {
        source: redacted("source").unwrap_or_default(),
        external_id: redacted("external_id"),
        dedup_key: get("dedup_key").unwrap_or_default(),
        title: redacted("title").unwrap_or_default(),
        resource: redacted("resource"),
        severity_raw: get("severity_raw"),
        severity_hint: get("severity_hint"),
        // `redact_json_bounded` returns None for oversized payloads — the
        // store additionally bounds bytes (`MAX_RAW_BYTES`).
        raw: entry
            .get("raw")
            .and_then(talos_dlp_provider::redact_json_bounded),
    }
}

/// Apply ONE entry for `user_id`: classify → redact → ingest or resolve.
///
/// The single home of the per-entry rules, shared by the `__ops_alert__`
/// envelope and the MCP `report_ops_alert` tool:
///   * the reserved `talos` source / `talos/` dedup prefix is REFUSED
///     before anything is read or written ([`classify_entry`]);
///   * `status_event: "resolved"` resolves, any other value is refused,
///     absence ingests;
///   * every free-text field is DLP-redacted before persistence
///     ([`redacted_alert`]) and `raw` is bounded.
///
/// Counts the outcome on `ops_alert_ingest_failures_total{reason}` /
/// `ops_alert_auto_resolved_total`, so every surface is counted alike.
/// The caller owns tenancy (`user_id`, `org_id`) and what it reports.
pub async fn apply_entry(
    repo: &crate::OpsAlertRepository,
    user_id: Uuid,
    org_id: Option<Uuid>,
    entry: &JsonValue,
) -> Result<EntryOutcome, EntryRefusal> {
    let result = match classify_entry(entry) {
        EntryAction::SkipReservedNamespace { dedup_key } => {
            Err(EntryRefusal::ReservedNamespace { dedup_key })
        }
        EntryAction::SkipUnknownStatusEvent { status_event } => {
            Err(EntryRefusal::UnknownStatusEvent { status_event })
        }
        // A recovery signal must RESOLVE the rolling alert, never ingest
        // it: a plain ingest would bump the row (and reopen an
        // operator-resolved one) — the exact wrong reading.
        EntryAction::Resolve { dedup_key } => {
            match repo.resolve_by_dedup_key(user_id, &dedup_key).await {
                Ok(true) => Ok(EntryOutcome::Resolved),
                Ok(false) => Ok(EntryOutcome::NoActiveAlert),
                Err(e) => Err(EntryRefusal::Resolve(e)),
            }
        }
        EntryAction::Ingest => repo
            .ingest(user_id, org_id, redacted_alert(entry))
            .await
            .map(EntryOutcome::Ingested)
            .map_err(EntryRefusal::Ingest),
    };
    match &result {
        Ok(EntryOutcome::Resolved) => {
            if let Some(m) = talos_metrics::global() {
                m.ops_alert_auto_resolved_total.inc();
            }
        }
        Ok(_) => {}
        Err(refusal) => {
            if let Some(reason) = refusal.metric_label() {
                bump_failure_metric(reason);
            }
        }
    }
    result
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
            // Classify → redact → ingest/resolve, and its counters, are
            // [`apply_entry`]'s; this loop only logs the outcome.
            match apply_entry(&repo, user_id, org_id, &a).await {
                Ok(EntryOutcome::Ingested(outcome)) => {
                    tracing::debug!(%actor_id, context, ?outcome, "__ops_alert__ ingested");
                }
                Ok(EntryOutcome::Resolved) => {
                    tracing::info!(
                        %actor_id, context,
                        dedup_key = a.get("dedup_key").and_then(JsonValue::as_str).unwrap_or_default(),
                        "__ops_alert__: alert auto-resolved by source recovery signal"
                    );
                }
                Ok(EntryOutcome::NoActiveAlert) => {
                    // Never-seen or already-resolved — normal.
                    tracing::debug!(
                        %actor_id, context,
                        dedup_key = a.get("dedup_key").and_then(JsonValue::as_str).unwrap_or_default(),
                        "__ops_alert__: resolve signal matched no active alert"
                    );
                }
                Err(EntryRefusal::ReservedNamespace { dedup_key }) => {
                    tracing::warn!(
                        %actor_id, context, dedup_key,
                        "__ops_alert__: entry claims the reserved 'talos' namespace — dropped \
                         (module-emitted alerts cannot touch self-monitoring rows)"
                    );
                }
                Err(EntryRefusal::UnknownStatusEvent { status_event }) => {
                    tracing::warn!(
                        %actor_id, context, status_event,
                        "__ops_alert__: unknown status_event — entry skipped"
                    );
                }
                Err(EntryRefusal::Resolve(e)) => {
                    tracing::warn!(%actor_id, context, error = %e, "__ops_alert__ auto-resolve failed");
                }
                Err(EntryRefusal::Ingest(e)) => {
                    let reason = e.metric_label();
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
    fn reserved_namespace_is_refused_in_both_directions() {
        // Ingest-shaped entry claiming a talos/ dedup key → skipped.
        assert!(matches!(
            classify_entry(&json!({"dedup_key": "talos/wf/node/fuel_exhausted",
                                   "source": "custom", "title": "spoof"})),
            EntryAction::SkipReservedNamespace { .. }
        ));
        // Resolve-shaped entry targeting a talos/ key → skipped (a
        // module must not be able to suppress self-monitoring alerts).
        assert!(matches!(
            classify_entry(&json!({"dedup_key": "talos/wf/node/auth",
                                   "status_event": "resolved"})),
            EntryAction::SkipReservedNamespace { .. }
        ));
        // Claiming the platform source without the prefix → skipped too.
        assert!(matches!(
            classify_entry(&json!({"dedup_key": "custom/key", "source": "talos",
                                   "title": "spoof"})),
            EntryAction::SkipReservedNamespace { .. }
        ));
        // Ordinary sources are untouched.
        assert!(matches!(
            classify_entry(
                &json!({"dedup_key": "gcpmon|p|r", "source": "gcp-monitoring",
                                   "title": "ok"})
            ),
            EntryAction::Ingest
        ));
    }

    #[test]
    fn classify_entry_routes_status_events() {
        assert_eq!(
            classify_entry(&json!({"dedup_key": "k", "source": "s", "title": "t"})),
            EntryAction::Ingest
        );
        assert_eq!(
            classify_entry(&json!({"dedup_key": "gcpmon|p|r", "status_event": "resolved"})),
            EntryAction::Resolve {
                dedup_key: "gcpmon|p|r".into()
            }
        );
        // Unknown status_event must NOT fall through to ingest — a typo
        // in a recovery event turning into a bump would reopen
        // operator-resolved alerts.
        assert_eq!(
            classify_entry(&json!({"dedup_key": "k", "status_event": "closed"})),
            EntryAction::SkipUnknownStatusEvent {
                status_event: "closed".into()
            }
        );
        // Resolve with a missing dedup_key classifies as Resolve with an
        // empty key; the repo layer no-ops on empty keys.
        assert_eq!(
            classify_entry(&json!({"status_event": "resolved"})),
            EntryAction::Resolve {
                dedup_key: String::new()
            }
        );
        // Non-string status_event is treated as absent (ingest) — the
        // field contract is string-typed.
        assert_eq!(
            classify_entry(&json!({"dedup_key": "k", "status_event": 7})),
            EntryAction::Ingest
        );
    }

    /// A repository whose pool can never connect: `connect_lazy` opens
    /// nothing until a statement runs, and the address refuses at once. A
    /// refusal that returns BEFORE any statement is reported as itself; one
    /// that reached the database would come back as a db error instead.
    fn unreachable_repo() -> crate::OpsAlertRepository {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect_lazy("postgres://nobody:nothing@127.0.0.1:1/none")
            .expect("lazy pool");
        crate::OpsAlertRepository::new(pool)
    }

    #[tokio::test]
    async fn apply_entry_refuses_the_reserved_namespace_before_any_statement() {
        let repo = unreachable_repo();
        let user = Uuid::new_v4();
        for entry in [
            // Raise under a reserved dedup key.
            json!({"source": "backup-drill", "dedup_key": "talos/wf/x/auth", "title": "spoof"}),
            // Raise under the reserved source.
            json!({"source": "talos", "dedup_key": "backup-drill|artifact", "title": "spoof"}),
            // Resolve a reserved key — would silence self-monitoring.
            json!({"source": "backup-drill", "dedup_key": "talos/wf/x/auth",
                   "status_event": "resolved"}),
        ] {
            match apply_entry(&repo, user, None, &entry).await {
                Err(EntryRefusal::ReservedNamespace { .. }) => {}
                other => panic!("{entry}: expected a reserved-namespace refusal, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn apply_entry_refuses_an_unknown_status_event_before_any_statement() {
        let entry = json!({"source": "s", "dedup_key": "k", "title": "t",
                           "status_event": "closed"});
        match apply_entry(&unreachable_repo(), Uuid::new_v4(), None, &entry).await {
            Err(EntryRefusal::UnknownStatusEvent { status_event }) => {
                assert_eq!(status_event, "closed");
            }
            other => panic!("expected an unknown-status_event refusal, got {other:?}"),
        }
    }

    #[test]
    fn refusal_metric_labels_keep_the_envelope_vocabulary() {
        assert_eq!(
            EntryRefusal::ReservedNamespace {
                dedup_key: "talos/x".into()
            }
            .metric_label(),
            Some("namespace")
        );
        assert_eq!(
            EntryRefusal::UnknownStatusEvent {
                status_event: "closed".into()
            }
            .metric_label(),
            None
        );
        assert_eq!(
            EntryRefusal::Resolve(anyhow::anyhow!("x")).metric_label(),
            Some("db")
        );
        assert_eq!(
            EntryRefusal::Ingest(crate::OpsAlertIngestError::Validation("x".into())).metric_label(),
            Some("validation")
        );
    }

    #[test]
    fn redacted_alert_redacts_free_text_and_keeps_the_dedup_key() {
        let entry = json!({
            "source": "backup-drill",
            "dedup_key": "backup-drill|artifact",
            "title": "drill failed for SSN: 123-45-6789",
            "resource": "SSN: 123-45-6789",
            "external_id": "SSN: 123-45-6789",
            "severity_hint": "high",
            "raw": {"reason": "SSN: 123-45-6789"},
        });
        let a = redacted_alert(&entry);
        assert_eq!(a.dedup_key, "backup-drill|artifact");
        for (field, value) in [
            ("title", a.title.as_str()),
            ("resource", a.resource.as_deref().unwrap_or_default()),
            ("external_id", a.external_id.as_deref().unwrap_or_default()),
        ] {
            assert!(!value.contains("123-45-6789"), "{field}: {value}");
            assert!(value.contains("[REDACTED:SSN]"), "{field}: {value}");
        }
        let raw = a.raw.expect("raw kept").to_string();
        assert!(!raw.contains("123-45-6789"), "{raw}");
        assert_eq!(a.severity_hint.as_deref(), Some("high"));
    }

    #[test]
    fn presence_probe_matches_extraction_gate() {
        assert!(output_has_envelope(
            &json!({"__ops_alert__": {"alerts": []}})
        ));
        assert!(!output_has_envelope(&json!({"anything": "else"})));
    }
}
