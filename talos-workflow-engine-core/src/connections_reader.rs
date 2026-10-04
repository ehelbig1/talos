//! Read-side port for the running user's connected services.
//!
//! The `connections` system node executes CONTROLLER-side — which services
//! a user has connected, and where each credential is stored, are
//! controller data (workers stay credential-free) — so the engine reaches
//! them through an injected trait object, like [`crate::OpsAlertsReader`].
//! The Postgres impl lives in `talos-engine`.
//!
//! ## What the node is for
//!
//! A workflow that reads "my banks" or "my calendars" had one hand-wired
//! node per account, so an account connected later was not read until
//! someone edited the graph, and nothing said so. This node gives a
//! workflow the list, so a composer can at least say what it did not read.
//!
//! ## What it deliberately does not do
//!
//! It emits each connection's `vault://` REFERENCE (a string naming where
//! the credential is), never a credential. And a reference arriving in a
//! node's INPUT is not resolved at dispatch — the engine ships a secret only
//! for a reference in the node's own configuration — so this node's output
//! does not, by itself, let a downstream module use a credential its author
//! did not name.

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Whether `provider` has the shape of a service id (`plaid`,
/// `google-calendar`): 1 to 40 lowercase letters, digits, `-` or `_`.
///
/// The graph parser reads a value that fails this as "no filter", so the
/// authoring tool refuses one rather than letting a typo widen the listing.
#[must_use]
pub fn provider_id_usable(provider: &str) -> bool {
    !provider.is_empty()
        && provider.len() <= 40
        && provider
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Fetch the caller's connections.
#[async_trait]
pub trait ConnectionsReader: Send + Sync {
    /// Returns a JSON object shaped:
    /// `{ "count": N, "truncated": bool, "stored_checked": bool,
    ///    "connections": [ {service, name, account, connected_at,
    ///    vault_reference, allowed_secrets, stored, module_readable, …} ] }`.
    ///
    /// `user_id` is the TENANT scope — impls MUST filter every query by it
    /// (it comes from the execution's resolved identity, never from node
    /// config). `provider` keeps one service's connections; `None` keeps
    /// all.
    async fn connections(
        &self,
        user_id: Uuid,
        provider: Option<&str>,
    ) -> Result<JsonValue, crate::BoxError>;
}

// ── Per-connection fan-out ──────────────────────────────────────────────────
//
// A `for_each_connection` node runs ITS OWN module once per connection of
// one service. What differs between the runs is a handful of the module's
// config keys, written by the engine from the connection listing. Planning
// which runs happen, and assembling their results, are the pure functions
// below; the engine supplies the listing, the grant check and the dispatch.

/// The key in a node's `data` that holds the fan-out settings. Removed from
/// the config a run's module receives.
pub const FOR_EACH_CONNECTION_KEY: &str = "for_each_connection";
/// Most connections one node runs. The rest are counted, not run.
pub const MAX_FAN_OUT: u32 = 16;
/// Connections run when the node does not say.
pub const DEFAULT_FAN_OUT: u32 = 8;
/// Most config keys a node may bind.
pub const MAX_BINDINGS: usize = 8;
/// Runs in flight at once.
pub const FAN_OUT_CONCURRENCY: usize = 4;
const MAX_REASON_CHARS: usize = 240;

/// What of a connection a config key is set to.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionField {
    /// The `vault://` reference the connection's credential is stored at.
    VaultReference,
    /// The account's label (an address, a bank's name).
    Account,
    /// The service id (`plaid`, `gmail`).
    Service,
    /// When the connection was made (RFC 3339).
    ConnectedAt,
}

impl ConnectionField {
    /// The spelling used in graph JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VaultReference => "vault_reference",
            Self::Account => "account",
            Self::Service => "service",
            Self::ConnectedAt => "connected_at",
        }
    }

    /// Parse the graph-JSON spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        [
            Self::VaultReference,
            Self::Account,
            Self::Service,
            Self::ConnectedAt,
        ]
        .into_iter()
        .find(|f| f.as_str() == s)
    }
}

/// Whether `key` may be bound: a config key a module reads, never an
/// engine-reserved one (`__…`) and never the fan-out's own settings.
#[must_use]
pub fn binding_key_usable(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && !key.starts_with("__")
        && key != FOR_EACH_CONNECTION_KEY
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Read a node's fan-out settings from `data.for_each_connection`:
/// `{provider, bind: {CONFIG_KEY: field}, max_connections?}`. `None` when
/// the provider is unusable or no binding survives — a node that would run
/// its module with nothing set per connection is not a fan-out.
#[must_use]
pub fn parse_for_each_connection(
    data: &JsonValue,
) -> Option<(
    String,
    std::collections::BTreeMap<String, ConnectionField>,
    u32,
)> {
    let settings = data.get(FOR_EACH_CONNECTION_KEY)?;
    let provider = settings
        .get("provider")
        .and_then(JsonValue::as_str)
        .filter(|p| provider_id_usable(p))?
        .to_string();
    let bind: std::collections::BTreeMap<String, ConnectionField> = settings
        .get("bind")
        .and_then(JsonValue::as_object)?
        .iter()
        .filter(|(key, _)| binding_key_usable(key))
        .filter_map(|(key, field)| Some((key.clone(), ConnectionField::parse(field.as_str()?)?)))
        .take(MAX_BINDINGS)
        .collect();
    if bind.is_empty() {
        return None;
    }
    let max = settings
        .get("max_connections")
        .and_then(JsonValue::as_u64)
        .map_or(DEFAULT_FAN_OUT, |n| {
            u32::try_from(n.clamp(1, u64::from(MAX_FAN_OUT))).unwrap_or(MAX_FAN_OUT)
        });
    Some((provider, bind, max))
}

/// One run the node will make: the config keys set for it.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionRun {
    /// The account's label, for the report.
    pub account: String,
    /// The service id.
    pub service: String,
    /// Config keys written for this run, replacing any the node set.
    pub overlay: serde_json::Map<String, JsonValue>,
}

/// A connection that is listed and not run, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionSkip {
    /// The account's label.
    pub account: String,
    /// `no_reference`, `not_stored` or `not_granted`.
    pub reason: &'static str,
}

/// Which connections a node runs.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ConnectionPlan {
    /// The runs, in listing order.
    pub runs: Vec<ConnectionRun>,
    /// Connections listed and not run.
    pub skipped: Vec<ConnectionSkip>,
    /// Connections the listing held for this service.
    pub listed: usize,
    /// Runnable connections past the node's limit.
    pub not_run: usize,
    /// The listing itself was cut short.
    pub truncated: bool,
}

/// Decide the runs from a [`ConnectionsReader`] listing.
///
/// A connection is run only when everything bound can be supplied. When a
/// key is bound to the credential reference, that means: the listing names a
/// reference a module may read, the vault is not known to lack it, and
/// `permitted(path)` — the module's own secrets grant — admits it. The grant
/// is checked here so a connection the worker would refuse is reported as
/// skipped instead of dispatched to fail.
///
/// Only entries whose `service` is `provider` are considered, whatever the
/// listing holds.
#[must_use]
pub fn plan_connection_runs(
    listing: &JsonValue,
    provider: &str,
    bind: &std::collections::BTreeMap<String, ConnectionField>,
    max: u32,
    permitted: impl Fn(&str) -> bool,
) -> ConnectionPlan {
    let mut plan = ConnectionPlan {
        truncated: listing
            .get("truncated")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false),
        ..ConnectionPlan::default()
    };
    let needs_credential = bind.values().any(|f| *f == ConnectionField::VaultReference);
    let text = |entry: &JsonValue, key: &str| {
        entry
            .get(key)
            .and_then(JsonValue::as_str)
            .unwrap_or("")
            .to_string()
    };
    let entries = listing
        .get("connections")
        .and_then(JsonValue::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for entry in entries {
        if entry.get("service").and_then(JsonValue::as_str) != Some(provider) {
            continue;
        }
        plan.listed += 1;
        let account = text(entry, "account");
        if needs_credential {
            let reference = entry.get("vault_reference").and_then(JsonValue::as_str);
            let Some(path) = reference.and_then(|r| r.strip_prefix("vault://")) else {
                plan.skipped.push(ConnectionSkip {
                    account,
                    reason: "no_reference",
                });
                continue;
            };
            // `stored: null` is "could not be checked"; only a known absence skips.
            if entry.get("stored").and_then(JsonValue::as_bool) == Some(false) {
                plan.skipped.push(ConnectionSkip {
                    account,
                    reason: "not_stored",
                });
                continue;
            }
            if !permitted(path) {
                plan.skipped.push(ConnectionSkip {
                    account,
                    reason: "not_granted",
                });
                continue;
            }
        }
        if plan.runs.len() >= max as usize {
            plan.not_run += 1;
            continue;
        }
        let overlay = bind
            .iter()
            .map(|(key, field)| (key.clone(), JsonValue::String(text(entry, field.as_str()))))
            .collect();
        plan.runs.push(ConnectionRun {
            service: text(entry, "service"),
            account,
            overlay,
        });
    }
    plan
}

fn bounded_reason(reason: &str) -> String {
    let flat: String = reason
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_REASON_CHARS)
        .collect();
    flat.trim().to_string()
}

/// An error envelope for the node itself (the listing could not be read, or
/// nothing could be run).
#[must_use]
pub fn for_each_error(provider: &str, message: &str) -> JsonValue {
    serde_json::json!({
        "__error": true,
        "error_message": bounded_reason(message),
        "items": [],
        "count": 0,
        "connections": { "provider": provider },
    })
}

/// The node's output: the runs' outputs in listing order under `items`
/// (the shape a `collect` node emits, so a consumer of one reads the
/// other), a failed run as an error envelope naming its account, and a
/// `connections` report of what was listed, read, failed, skipped and left
/// unrun.
///
/// The node reports an error only when connections exist and NONE was read:
/// one bank failing is a gap the consumer is told about, every bank failing
/// is a failed read.
#[must_use]
pub fn for_each_output(
    provider: &str,
    plan: &ConnectionPlan,
    results: Vec<Result<JsonValue, String>>,
) -> JsonValue {
    let mut items = Vec::with_capacity(results.len());
    let mut failed = Vec::new();
    let mut read = 0usize;
    for (run, result) in plan.runs.iter().zip(results) {
        match result {
            Ok(output) => {
                read += 1;
                items.push(output);
            }
            Err(reason) => {
                let reason = bounded_reason(&reason);
                items.push(serde_json::json!({
                    "__error": true,
                    "error_message": reason,
                    "account": run.account,
                    "service": run.service,
                }));
                failed.push(serde_json::json!({ "account": run.account, "reason": reason }));
            }
        }
    }
    let skipped: Vec<JsonValue> = plan
        .skipped
        .iter()
        .map(|s| serde_json::json!({ "account": s.account, "reason": s.reason }))
        .collect();
    let mut out = serde_json::json!({
        "count": items.len(),
        "items": items,
        "connections": {
            "provider": provider,
            "listed": plan.listed,
            "read": read,
            "failed": failed,
            "skipped": skipped,
            "not_run": plan.not_run,
            "truncated": plan.truncated,
        },
    });
    if plan.listed > 0 && read == 0 {
        out["__error"] = JsonValue::Bool(true);
        out["error_message"] = JsonValue::String(format!(
            "none of the {} {provider} connection(s) could be read",
            plan.listed
        ));
    }
    out
}

#[cfg(test)]
mod for_each_tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn bind() -> BTreeMap<String, ConnectionField> {
        BTreeMap::from([
            ("ACCESS_TOKEN".to_string(), ConnectionField::VaultReference),
            ("INSTITUTION".to_string(), ConnectionField::Account),
        ])
    }
    fn bank(account: &str, item: &str) -> JsonValue {
        json!({"service": "plaid", "account": account, "connected_at": "2026-10-03T00:00:00+00:00",
               "vault_reference": format!("vault://plaid/access_token/{item}"), "stored": true, "module_readable": true})
    }
    fn granted(path: &str) -> bool {
        path.starts_with("plaid/access_token/")
    }

    #[test]
    fn each_connection_gets_its_own_reference_and_nothing_else() {
        let listing = json!({"connections": [bank("First Bank", "a"), bank("Second Bank", "b")]});
        let plan = plan_connection_runs(&listing, "plaid", &bind(), 8, granted);
        assert_eq!(
            (plan.listed, plan.runs.len(), plan.skipped.len()),
            (2, 2, 0)
        );
        assert_eq!(
            JsonValue::Object(plan.runs[0].overlay.clone()),
            json!({"ACCESS_TOKEN": "vault://plaid/access_token/a", "INSTITUTION": "First Bank"})
        );
        assert_eq!(
            JsonValue::Object(plan.runs[1].overlay.clone()),
            json!({"ACCESS_TOKEN": "vault://plaid/access_token/b", "INSTITUTION": "Second Bank"})
        );
    }

    #[test]
    fn a_connection_the_module_may_not_read_is_skipped_not_run() {
        let mut controller_only = bank("Cloud", "c");
        controller_only["vault_reference"] = JsonValue::Null;
        let mut absent = bank("Gone Bank", "d");
        absent["stored"] = json!(false);
        let mut unknown = bank("Unchecked Bank", "e");
        unknown["stored"] = JsonValue::Null;
        let listing = json!({"connections": [
            bank("First Bank", "a"), controller_only, absent, unknown,
            // The listing is for one service; an entry of another is not this node's.
            {"service": "gmail", "account": "me@example.com", "vault_reference": "vault://plaid/access_token/x", "stored": true},
        ]});
        // The grant admits nothing: every credentialed run is skipped.
        let none = plan_connection_runs(&listing, "plaid", &bind(), 8, |_| false);
        assert!(none.runs.is_empty());
        assert_eq!(none.listed, 4);
        let reasons: Vec<&str> = none.skipped.iter().map(|s| s.reason).collect();
        assert_eq!(
            reasons,
            ["not_granted", "no_reference", "not_stored", "not_granted"]
        );

        let some = plan_connection_runs(&listing, "plaid", &bind(), 8, granted);
        let ran: Vec<&str> = some.runs.iter().map(|r| r.account.as_str()).collect();
        assert_eq!(
            ran,
            ["First Bank", "Unchecked Bank"],
            "an unchecked vault is tried"
        );
        assert!(!format!("{:?}", some.runs).contains("me@example.com"));
    }

    #[test]
    fn runs_past_the_limit_are_counted_not_run() {
        let listing = json!({"truncated": true, "connections": (0..5).map(|i| bank(&format!("Bank {i}"), &i.to_string())).collect::<Vec<_>>()});
        let plan = plan_connection_runs(&listing, "plaid", &bind(), 3, granted);
        assert_eq!(
            (plan.runs.len(), plan.not_run, plan.truncated),
            (3, 2, true)
        );
    }

    #[test]
    fn a_binding_without_a_credential_needs_no_grant() {
        let only_name = BTreeMap::from([("ACCOUNT".to_string(), ConnectionField::Account)]);
        let mut entry = bank("First Bank", "a");
        entry["vault_reference"] = JsonValue::Null;
        let plan = plan_connection_runs(
            &json!({"connections": [entry]}),
            "plaid",
            &only_name,
            8,
            |_| false,
        );
        assert_eq!(plan.runs.len(), 1);
        assert_eq!(
            JsonValue::Object(plan.runs[0].overlay.clone()),
            json!({"ACCOUNT": "First Bank"})
        );
    }

    #[test]
    fn settings_are_read_bounded_and_refused_when_unusable() {
        let ok = parse_for_each_connection(&json!({"for_each_connection": {
            "provider": "plaid", "max_connections": 999,
            "bind": {"ACCESS_TOKEN": "vault_reference", "INSTITUTION": "account",
                     "__actor_context__": "account", "for_each_connection": "account",
                     "bad key": "account", "OTHER": "password"}}}))
        .expect("usable");
        assert_eq!(ok.0, "plaid");
        assert_eq!(
            ok.1,
            bind(),
            "reserved, unusable and unknown bindings are dropped"
        );
        assert_eq!(ok.2, MAX_FAN_OUT);
        for bad in [
            json!({}),
            json!({"for_each_connection": {"provider": "Plaid", "bind": {"A": "account"}}}),
            json!({"for_each_connection": {"provider": "plaid", "bind": {}}}),
            json!({"for_each_connection": {"provider": "plaid", "bind": {"__x": "account"}}}),
            json!({"for_each_connection": {"provider": "plaid"}}),
        ] {
            assert!(parse_for_each_connection(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn one_failure_is_a_gap_and_none_read_is_an_error() {
        let listing = json!({"connections": [bank("First Bank", "a"), bank("Second Bank", "b")]});
        let plan = plan_connection_runs(&listing, "plaid", &bind(), 8, granted);
        let partial = for_each_output(
            "plaid",
            &plan,
            vec![
                Ok(json!({"balance": 1})),
                Err("HTTP 500\nfrom the bank".into()),
            ],
        );
        assert!(partial.get("__error").is_none(), "{partial}");
        assert_eq!(partial["count"], json!(2));
        assert_eq!(partial["items"][0], json!({"balance": 1}));
        assert_eq!(partial["items"][1]["account"], json!("Second Bank"));
        assert_eq!(
            partial["items"][1]["error_message"],
            json!("HTTP 500 from the bank")
        );
        assert_eq!(partial["connections"]["read"], json!(1));
        assert_eq!(
            partial["connections"]["failed"][0]["account"],
            json!("Second Bank")
        );

        let none = for_each_output("plaid", &plan, vec![Err("x".into()), Err("y".into())]);
        assert_eq!(none["__error"], json!(true));

        // Nothing connected is an empty read, not a failed one.
        let empty = for_each_output("plaid", &ConnectionPlan::default(), vec![]);
        assert!(empty.get("__error").is_none());
        assert_eq!(empty["items"], json!([]));

        // Connected, and every one skipped: nothing was read.
        let skipped = plan_connection_runs(&listing, "plaid", &bind(), 8, |_| false);
        let out = for_each_output("plaid", &skipped, vec![]);
        assert_eq!(out["__error"], json!(true));
        assert_eq!(
            out["connections"]["skipped"][0]["reason"],
            json!("not_granted")
        );
    }
}
