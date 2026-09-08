//! One operator-facing view of every push channel, and the ONE decision about
//! what a channel's module binding means.
//!
//! # Why this crate exists
//!
//! A push channel (Gmail watch, Google Calendar watch, Google Cloud Pub/Sub
//! subscription) may bind a WASM **module**: one inbound event → one dispatched
//! module job. The binding is a `module_id` copied verbatim out of the create
//! request into an AEAD-encrypted `integration_state` row. Nothing validated it
//! at create time and nothing outside the dispatch path ever read it back, so a
//! channel bound to a module that does not exist looked healthy from every
//! surface an operator consults while EVERY push to it failed. Measured live
//! 2026-09-07: the fleet's only module-binding channel had been in exactly that
//! state since 2026-07-17.
//!
//! The obvious fix — let the MCP handlers and the hygiene service read the
//! channel rows — inverts the layering: those crates sit BELOW the integration
//! crates and must not depend on them. So the integration crates implement
//! [`PushChannelInventory`] here, and the controller injects the set.
//!
//! # What may cross this boundary
//!
//! [`PushChannelRow`] carries an identity, a display name and a classification.
//! It carries **no push token, no endpoint (the GCP endpoint embeds the raw
//! token), and no payload** — those are the create-response and the
//! owner-scoped REST list's business, not an operator report's.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// What a channel's `module_id` means. FOUR-valued, because `module_name:
/// null` was three states rendered identically until 2026-09-07.
///
/// * [`ModuleBinding::None`] — the channel binds no module; a push is acked and
///   nothing is dispatched. Deliberate configuration, not a finding.
/// * [`ModuleBinding::Bound`] — the module exists for this user and will load.
/// * [`ModuleBinding::Missing`] — `module_id` is set and names no module this
///   user can load. **Every push to this channel fails.**
/// * [`ModuleBinding::Unreadable`] — the lookup ITSELF failed. Not a claim about
///   the binding: reporting `Missing` here would be a determinate negative over
///   a query that did not answer (checks 74 / 79's class).
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ModuleBinding {
    None,
    Bound,
    Missing,
    Unreadable,
}

impl ModuleBinding {
    /// The wire spelling. Pinned, because `GET /api/gcp/watch-channels` has
    /// rendered these four strings since 2026-09-07 and a frontend reads them.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Bound => "bound",
            Self::Missing => "missing",
            Self::Unreadable => "unreadable",
        }
    }

    /// Whether this binding is a HYGIENE FINDING — a channel that is wired up,
    /// is being pushed to, and cannot do the thing it was created to do.
    ///
    /// `Unreadable` is deliberately NOT a finding: it is a statement about the
    /// query, and counting it would put a pool timeout in the same bucket as a
    /// permanently dead channel. It is disclosed separately instead.
    #[must_use]
    pub fn is_dangling(self) -> bool {
        matches!(self, Self::Missing)
    }
}

/// The one place the four binding states are decided, so no two readers can
/// disagree about what a `null` module name means.
///
/// It takes the LOOKUP'S OWN `Result`, not a pre-flattened `Option`, and that is
/// structural rather than stylistic. With an `Option` parameter the classifier
/// is perfectly correct and the CALL SITE can still hand it
/// `Some(HashMap::new())` on an `Err` — a one-line revert to the pre-fix
/// `.unwrap_or_default()` behaviour that every test here SURVIVES (measured
/// 2026-09-07 in `talos-google-cloud`, mutation M-V1d). Reading the `Result`
/// makes that collapse take a deliberate rewrite of the read instead of a
/// defaulted argument. It does not make it impossible; checks 74b and 79b both
/// state that a guard at the read cannot see an answer computed correctly and
/// then discarded.
pub fn classify_module_binding<E>(
    module_id: Option<Uuid>,
    names: &Result<HashMap<Uuid, String>, E>,
) -> ModuleBinding {
    match (module_id, names) {
        (None, _) => ModuleBinding::None,
        (Some(_), Err(_)) => ModuleBinding::Unreadable,
        (Some(id), Ok(map)) => {
            if map.contains_key(&id) {
                ModuleBinding::Bound
            } else {
                ModuleBinding::Missing
            }
        }
    }
}

/// A push-channel failure, flattened for the operator surfaces.
///
/// Deliberately NOT `talos_integration_helpers::RenewalFailure`: that crate
/// pulls in secrets-manager, envelope-seal, memory and reqwest, and this crate
/// exists to keep all of that out of the hygiene service. The integration
/// crates convert (they depend on both).
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct PushChannelFailure {
    pub error_message: String,
    pub failed_at: DateTime<Utc>,
    /// True when the error text matched the shared OAuth-dead heuristic
    /// (`talos_integration_helpers::looks_like_oauth_failure`) — the operator's
    /// repair is "reconnect the account", not "re-bind the module".
    pub likely_oauth_failure: bool,
}

/// One push channel, as an operator report may see it.
#[derive(Serialize, Debug, Clone)]
pub struct PushChannelRow {
    /// `"gmail"` / `"google_calendar"` / `"google_cloud"` — the
    /// `integration_state.integration_name`, so an operator can find the row.
    pub integration: &'static str,
    /// Our internal channel uuid. Pseudonymous: it is the identifier the audit
    /// rows and the dispatch WARN carry, and it is NOT the push token.
    pub channel_id: Uuid,
    pub display_name: String,
    pub module_id: Option<Uuid>,
    /// Present only when the binding is [`ModuleBinding::Bound`] — a name for a
    /// module the lookup did not find would be a fabrication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_name: Option<String>,
    pub module_binding: ModuleBinding,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_event_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_failure: Option<PushChannelFailure>,
}

impl PushChannelRow {
    /// The repair sentence for a dangling channel, so the report, the tool and
    /// any future surface cannot word it three ways.
    #[must_use]
    pub fn repair_hint(&self) -> String {
        format!(
            "Channel {} ({}) names module {}, which does not exist for this user \
             — every push to it fails at module load. Re-create the channel bound \
             to a module that exists, or stop the watch.",
            self.channel_id,
            self.integration,
            self.module_id
                .map(|m| m.to_string())
                .unwrap_or_else(|| "<none>".into()),
        )
    }
}

/// One integration's answer to "which push channels does this user own, and is
/// each one's module binding real?".
///
/// Implemented in the integration crates; consumed through
/// [`PushChannelInventorySet`] by callers that must not depend on them.
#[async_trait::async_trait]
pub trait PushChannelInventory: Send + Sync {
    /// The `integration_state.integration_name` this inventory speaks for.
    fn integration_name(&self) -> &'static str;

    /// Every push channel this user owns, classified. `Err` means the LIST read
    /// failed — a per-channel classification failure is
    /// [`ModuleBinding::Unreadable`] instead, and is not an error.
    async fn list_channels(&self, user_id: Uuid) -> anyhow::Result<Vec<PushChannelRow>>;
}

/// The set of inventories wired into this process, as one injectable value.
///
/// A newtype over the `Vec<Arc<dyn …>>` rather than the bare vec, following the
/// `talos_dlp_provider::DlpService` precedent: the consumer holds a concrete
/// type and the `dyn` stays here. An `Option<Arc<PushChannelInventorySet>>` on
/// the consumer distinguishes "not wired in this process" from "wired and
/// surveyed" — an empty `Vec` cannot.
#[derive(Clone, Default)]
pub struct PushChannelInventorySet {
    inventories: Vec<Arc<dyn PushChannelInventory>>,
}

impl std::fmt::Debug for PushChannelInventorySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushChannelInventorySet")
            .field(
                "integrations",
                &self
                    .inventories
                    .iter()
                    .map(|i| i.integration_name())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl PushChannelInventorySet {
    #[must_use]
    pub fn new(inventories: Vec<Arc<dyn PushChannelInventory>>) -> Self {
        Self { inventories }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inventories.is_empty()
    }

    /// Ask every wired inventory, and keep the two halves apart: an integration
    /// that failed to answer does NOT make the ones that answered unreportable,
    /// and it does not silently vanish either — it is named in
    /// [`PushChannelSurvey::unreadable_integrations`].
    pub async fn survey(&self, user_id: Uuid) -> PushChannelSurvey {
        let mut survey = PushChannelSurvey::default();
        for inv in &self.inventories {
            let name = inv.integration_name();
            survey.surveyed_integrations.push(name);
            match inv.list_channels(user_id).await {
                Ok(rows) => survey.rows.extend(rows),
                Err(e) => {
                    tracing::warn!(
                        target: "talos_audit",
                        event_kind = "push_channel_inventory_unreadable",
                        integration = name,
                        %user_id,
                        error = %format!("{e:#}"),
                        "push-channel inventory read failed; \
                         this integration is disclosed as unreadable, not as empty"
                    );
                    survey.unreadable_integrations.push(name);
                }
            }
        }
        survey.rows.sort_by(|a, b| {
            a.integration
                .cmp(b.integration)
                .then_with(|| a.channel_id.cmp(&b.channel_id))
        });
        survey
    }
}

/// The result of asking every wired inventory.
#[derive(Debug, Default, Clone, Serialize)]
pub struct PushChannelSurvey {
    pub rows: Vec<PushChannelRow>,
    /// Integrations that were asked. A reader that sees an empty `rows` needs
    /// this to tell "nothing is configured" from "nobody looked".
    pub surveyed_integrations: Vec<&'static str>,
    /// Integrations whose LIST read failed. Their channels are absent from
    /// `rows` and no claim is made about them.
    pub unreadable_integrations: Vec<&'static str>,
}

impl PushChannelSurvey {
    /// Channels whose binding names a module that does not exist. Every push to
    /// each of these fails.
    #[must_use]
    pub fn dangling(&self) -> Vec<&PushChannelRow> {
        self.rows
            .iter()
            .filter(|r| r.module_binding.is_dangling())
            .collect()
    }

    /// Channels whose binding could not be classified. Separately disclosed —
    /// see [`ModuleBinding::is_dangling`] for why they are not folded in.
    #[must_use]
    pub fn unclassifiable(&self) -> Vec<&PushChannelRow> {
        self.rows
            .iter()
            .filter(|r| r.module_binding == ModuleBinding::Unreadable)
            .collect()
    }

    /// True when nothing about this survey is worth a report key. Distinct from
    /// "no rows": an integration that could not be read has something to say.
    #[must_use]
    pub fn has_nothing_to_report(&self) -> bool {
        self.dangling().is_empty()
            && self.unclassifiable().is_empty()
            && self.unreadable_integrations.is_empty()
    }
}

/// What a report knows about push channels. THREE-valued on purpose: the
/// middle state — "this process has no inventory wired, so nobody looked" — is
/// the one a two-valued `Option<Vec<_>>` cannot express, and it is the one that
/// must never render as an empty list.
#[derive(Debug, Clone)]
pub enum PushChannelReadout {
    /// No inventory was injected into this process. Say nothing rather than
    /// claiming a measured zero.
    NotConsulted,
    Surveyed(PushChannelSurvey),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(binding: ModuleBinding, module_id: Option<Uuid>) -> PushChannelRow {
        PushChannelRow {
            integration: "google_cloud",
            channel_id: Uuid::nil(),
            display_name: "probe".into(),
            module_id,
            module_name: None,
            module_binding: binding,
            created_at: None,
            last_event_at: None,
            recent_failure: None,
        }
    }

    /// A `module_name` of `null` is not one state. The live fleet's one bound
    /// channel was in the `missing` one — every push to it failing, and no
    /// field anywhere saying so.
    #[test]
    fn classification_is_four_valued() {
        let id = Uuid::new_v4();
        let mut map = HashMap::new();
        map.insert(id, "GCP: Alert Normalize".to_string());
        let known: Result<HashMap<Uuid, String>, &str> = Ok(map);
        let unreadable: Result<HashMap<Uuid, String>, &str> = Err("pool timeout");
        let empty: Result<HashMap<Uuid, String>, &str> = Ok(HashMap::new());

        assert_eq!(classify_module_binding(None, &known), ModuleBinding::None);
        assert_eq!(
            classify_module_binding(Some(id), &known),
            ModuleBinding::Bound
        );
        assert_eq!(
            classify_module_binding(Some(Uuid::new_v4()), &known),
            ModuleBinding::Missing
        );
        // The query did not answer. `Missing` here would be a determinate
        // negative over a read that failed — exactly what the pre-fix
        // `.unwrap_or_default()` produced.
        assert_eq!(
            classify_module_binding(Some(id), &unreadable),
            ModuleBinding::Unreadable
        );
        // …and an unreadable lookup must not claim the unbound case away either.
        assert_eq!(
            classify_module_binding(None, &unreadable),
            ModuleBinding::None
        );
        // An EMPTY but ANSWERED map is `missing`, not `unreadable`.
        assert_eq!(
            classify_module_binding(Some(id), &empty),
            ModuleBinding::Missing
        );
    }

    /// The wire spellings are what `GET /api/gcp/watch-channels` has rendered
    /// since 2026-09-07. Renaming one is a frontend break, not a refactor.
    #[test]
    fn wire_spellings_are_pinned() {
        assert_eq!(ModuleBinding::None.as_str(), "none");
        assert_eq!(ModuleBinding::Bound.as_str(), "bound");
        assert_eq!(ModuleBinding::Missing.as_str(), "missing");
        assert_eq!(ModuleBinding::Unreadable.as_str(), "unreadable");
        assert_eq!(
            serde_json::to_string(&ModuleBinding::Missing).unwrap(),
            "\"missing\""
        );
    }

    /// Only `Missing` is a finding. An `Unreadable` in the dangling count would
    /// put a pool timeout in the same bucket as a permanently dead channel.
    #[test]
    fn only_a_missing_binding_is_a_finding() {
        assert!(ModuleBinding::Missing.is_dangling());
        assert!(!ModuleBinding::Unreadable.is_dangling());
        assert!(!ModuleBinding::Bound.is_dangling());
        assert!(!ModuleBinding::None.is_dangling());
    }

    #[test]
    fn a_survey_separates_the_two_disclosures() {
        let survey = PushChannelSurvey {
            rows: vec![
                row(ModuleBinding::Bound, Some(Uuid::new_v4())),
                row(ModuleBinding::Missing, Some(Uuid::new_v4())),
                row(ModuleBinding::Unreadable, Some(Uuid::new_v4())),
                row(ModuleBinding::None, None),
            ],
            surveyed_integrations: vec!["google_cloud"],
            unreadable_integrations: vec![],
        };
        assert_eq!(survey.dangling().len(), 1);
        assert_eq!(survey.unclassifiable().len(), 1);
        assert!(!survey.has_nothing_to_report());
    }

    /// Nothing to say ⇒ no key. A fleet whose channels are all healthy must get
    /// a byte-identical report to a fleet with no channels at all.
    #[test]
    fn a_healthy_survey_has_nothing_to_report() {
        let survey = PushChannelSurvey {
            rows: vec![
                row(ModuleBinding::Bound, Some(Uuid::new_v4())),
                row(ModuleBinding::None, None),
            ],
            surveyed_integrations: vec!["gmail", "google_cloud"],
            unreadable_integrations: vec![],
        };
        assert!(survey.has_nothing_to_report());
    }

    /// …but an integration that could NOT be read has something to say even
    /// with zero rows. Otherwise a total read failure renders as "all clear".
    #[test]
    fn an_unreadable_integration_is_never_all_clear() {
        let survey = PushChannelSurvey {
            rows: vec![],
            surveyed_integrations: vec!["gmail"],
            unreadable_integrations: vec!["gmail"],
        };
        assert!(!survey.has_nothing_to_report());
        assert!(survey.dangling().is_empty());
    }

    /// The row that crosses this boundary must not carry the push token or the
    /// endpoint that embeds it.
    #[test]
    fn a_serialized_row_carries_no_token_or_endpoint() {
        let json =
            serde_json::to_string(&row(ModuleBinding::Missing, Some(Uuid::new_v4()))).unwrap();
        assert!(!json.contains("push_token"));
        assert!(!json.contains("push_endpoint"));
        assert!(!json.contains("endpoint"));
    }
}
