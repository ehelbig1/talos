//! Action links in a composed message — the engine's half.
//!
//! A compose node (the morning message, a bill reminder) wants "done",
//! "keep", "hold this time" to be links. It cannot mint one: a link is a
//! capability held by the controller, and a module runs in the
//! credential-free worker. So the module ASKS, in its output, and the
//! `action_links` system node — placed between the compose node and the
//! send node — answers:
//!
//! ```json
//! { "html": "… <a href=\"talos-action:done-12\">done</a> …",
//!   "__action_links__": [
//!     { "id": "done-12", "target": "list", "label": "Done: call the dentist",
//!       "payload": { "op": "done", "item": 12 },
//!       "fallback": "mailto:me+todo@example.com?subject=done%2012" } ] }
//! ```
//!
//! The node mints one link per request and returns the same output with
//! every `talos-action:<id>` replaced by the link (or by the request's
//! `fallback`, or `#`, when the link could not be minted), the request key
//! removed, and an engine-authored [`ACTION_LINKS_REPORT`] in its place.
//!
//! # Who decides what a link may start
//!
//! The GRAPH AUTHOR, in the node's configuration: `targets` maps a short
//! name (`"list"`) to a workflow id. A module names a target, never a
//! workflow; a request naming anything else is refused. So a module — or
//! text that reached a module from outside — cannot make a link that starts
//! a workflow the author did not list here.
//!
//! # Why the placeholder is not `{{…}}`
//!
//! Module source is rendered through Handlebars at compile time when it
//! contains that syntax, so a `{{action:…}}` literal in a module would be
//! consumed (or refused) by the compiler. `talos-action:<id>` is inert
//! everywhere: it is a syntactically valid URL scheme, so an unreplaced one
//! in an `href` is a dead link and not a broken page.
//!
//! This file is pure: planning what to mint and applying the result are
//! functions of JSON, testable without an engine. Minting is the injected
//! [`ActionLinkMinter`] port, implemented controller-side.

use std::collections::{BTreeMap, HashSet};

use async_trait::async_trait;
use serde_json::{json, Map, Value as JsonValue};
use uuid::Uuid;

/// The key a module's output carries its link requests under.
pub const ACTION_LINKS_REQUEST: &str = "__action_links__";
/// The engine-authored report that replaces the request key.
pub const ACTION_LINKS_REPORT: &str = "__action_links_report__";
/// What a module writes where a link belongs, followed by the request id.
pub const ACTION_PLACEHOLDER_PREFIX: &str = "talos-action:";
/// What replaces a placeholder whose link was not minted and which named no
/// fallback: a link that goes nowhere.
pub const DEAD_LINK: &str = "#";
/// Most requests one node run acts on.
pub const MAX_ACTION_LINKS: usize = 64;
/// Most targets one node may be configured with.
pub const MAX_ACTION_TARGETS: usize = 16;
/// Longest request id / target name.
pub const MAX_ACTION_NAME_CHARS: usize = 40;
/// Longest fallback accepted from a module.
pub const MAX_FALLBACK_CHARS: usize = 2048;

/// One link to mint, resolved against the node's configured targets.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionLinkSpec {
    /// The workflow the link starts (from the node's configured targets).
    pub workflow_id: Uuid,
    /// What the confirmation page says the link does.
    pub label: String,
    /// The trigger input the workflow receives.
    pub payload: JsonValue,
}

/// One request from a module's output, after planning.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedLink {
    /// The request's id — what its placeholder names.
    pub id: String,
    /// What to put in place of the placeholder when the link is not minted.
    pub fallback: Option<String>,
    /// The link to mint, or why this request will not be.
    pub spec: Result<ActionLinkSpec, &'static str>,
}

/// Mint links controller-side.
#[async_trait]
pub trait ActionLinkMinter: Send + Sync {
    /// Mint one link per spec, order-aligned: `Ok(url)` or `Err(reason)`.
    ///
    /// `user_id` is the TENANT scope and comes from the execution's
    /// resolved identity, never from node configuration or module output.
    /// An implementation MUST refuse a spec whose workflow is not that
    /// user's. `ttl_hours` is the node's configured lifetime; an
    /// implementation clamps it.
    async fn mint(
        &self,
        user_id: Uuid,
        source_execution_id: Uuid,
        source_node: &str,
        ttl_hours: Option<u32>,
        specs: &[ActionLinkSpec],
    ) -> Result<Vec<Result<String, String>>, crate::BoxError>;
}

/// Whether `name` can be a request id or a target name: 1 to
/// [`MAX_ACTION_NAME_CHARS`] of `[A-Za-z0-9_-]`.
#[must_use]
pub fn action_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_ACTION_NAME_CHARS
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A fallback a module supplied, if it is one this node will write into the
/// output: a `mailto:` or `https:` link of bounded length with no control
/// characters or quotes. Anything else is dropped (the placeholder then
/// becomes [`DEAD_LINK`]) — a fallback is module-authored text that lands in
/// an `href`.
#[must_use]
pub fn acceptable_fallback(raw: &str) -> Option<String> {
    let ok_scheme = raw.starts_with("mailto:") || raw.starts_with("https://");
    let ok_chars = !raw
        .chars()
        .any(|c| c.is_control() || matches!(c, '"' | '\'' | '<' | '>' | ' '));
    (ok_scheme && ok_chars && raw.chars().count() <= MAX_FALLBACK_CHARS).then(|| raw.to_string())
}

/// Read the requests out of a node's input and resolve each against the
/// node's configured `targets`. Requests past [`MAX_ACTION_LINKS`], with an
/// unusable id, a repeated id, or an unknown target are planned as
/// refusals — reported, never silently dropped — except a request with no
/// usable id at all, which has no placeholder to answer and is only counted
/// (`unidentified`).
#[must_use]
pub fn plan_action_links(
    input: &JsonValue,
    targets: &BTreeMap<String, Uuid>,
) -> (Vec<PlannedLink>, usize) {
    let Some(requests) = input
        .get(ACTION_LINKS_REQUEST)
        .and_then(JsonValue::as_array)
    else {
        return (Vec::new(), 0);
    };
    let mut planned: Vec<PlannedLink> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut unidentified = 0usize;
    let mut accepted = 0usize;
    for request in requests {
        let Some(id) = request
            .get("id")
            .and_then(JsonValue::as_str)
            .filter(|id| action_name_valid(id))
        else {
            unidentified += 1;
            continue;
        };
        let fallback = request
            .get("fallback")
            .and_then(JsonValue::as_str)
            .and_then(acceptable_fallback);
        if !seen.insert(id.to_string()) {
            // The first request with this id stands; its placeholder is
            // already spoken for.
            continue;
        }
        let spec = if accepted >= MAX_ACTION_LINKS {
            Err("too_many_links")
        } else {
            match request
                .get("target")
                .and_then(JsonValue::as_str)
                .and_then(|name| targets.get(name))
            {
                None => Err("unknown_target"),
                Some(workflow_id) => {
                    accepted += 1;
                    Ok(ActionLinkSpec {
                        workflow_id: *workflow_id,
                        label: request
                            .get("label")
                            .and_then(JsonValue::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        payload: request.get("payload").cloned().unwrap_or_else(|| json!({})),
                    })
                }
            }
        };
        planned.push(PlannedLink {
            id: id.to_string(),
            fallback,
            spec,
        });
    }
    (planned, unidentified)
}

/// What one planned request came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLink {
    /// The request's id — what its placeholder names.
    pub id: String,
    /// The minted link, when there is one.
    pub url: Option<String>,
    /// What replaces the placeholder when there is no link.
    pub fallback: Option<String>,
    /// Why there is no link, when there is none.
    pub refused: Option<String>,
}

fn replace_placeholders(text: &str, ordered: &[(String, String)]) -> String {
    if !text.contains(ACTION_PLACEHOLDER_PREFIX) {
        return text.to_string();
    }
    let mut out = text.to_string();
    for (placeholder, replacement) in ordered {
        if out.contains(placeholder.as_str()) {
            out = out.replace(placeholder.as_str(), replacement);
        }
    }
    out
}

fn substitute(value: &mut JsonValue, ordered: &[(String, String)]) {
    match value {
        JsonValue::String(text) => {
            let replaced = replace_placeholders(text, ordered);
            if replaced != *text {
                *text = replaced;
            }
        }
        JsonValue::Array(items) => items.iter_mut().for_each(|v| substitute(v, ordered)),
        JsonValue::Object(map) => map.values_mut().for_each(|v| substitute(v, ordered)),
        _ => {}
    }
}

/// Apply the outcome to the node's input and return the node's output: every
/// placeholder replaced, the request key REMOVED, and the report written.
///
/// The report is set-or-replace and the request key is removed whatever
/// happened, so a downstream node never sees a request it might act on and
/// a module cannot author the report (the key is engine-authored and
/// stripped from inbound payloads).
///
/// `unavailable` is the reason minting could not be attempted at all (no
/// minter wired, no tenant identity, a failed or timed-out mint); every
/// placeholder then falls back.
#[must_use]
pub fn apply_action_links(
    input: JsonValue,
    resolved: &[ResolvedLink],
    unidentified: usize,
    unavailable: Option<&str>,
) -> JsonValue {
    let mut output = match input {
        JsonValue::Object(map) => map,
        // A non-object input carries no request and no report can be
        // attached to it; pass it through unchanged.
        other => return other,
    };
    output.remove(ACTION_LINKS_REQUEST);
    output.remove(ACTION_LINKS_REPORT);

    // Longest id first, so `done-1` never rewrites the front of `done-12`.
    let mut ordered: Vec<(String, String)> = resolved
        .iter()
        .map(|link| {
            let replacement = link
                .url
                .clone()
                .or_else(|| link.fallback.clone())
                .unwrap_or_else(|| DEAD_LINK.to_string());
            (
                format!("{ACTION_PLACEHOLDER_PREFIX}{}", link.id),
                replacement,
            )
        })
        .collect();
    ordered.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));

    let mut body = JsonValue::Object(output);
    substitute(&mut body, &ordered);
    let JsonValue::Object(mut output) = body else {
        unreachable!("an object stays an object under substitution")
    };

    let minted = resolved.iter().filter(|l| l.url.is_some()).count();
    let not_minted: Vec<JsonValue> = resolved
        .iter()
        .filter(|l| l.url.is_none())
        .map(|l| {
            json!({
                "id": l.id,
                "reason": l.refused.as_deref().unwrap_or("not_minted"),
                "fell_back": l.fallback.is_some(),
            })
        })
        .collect();
    let mut report = Map::new();
    report.insert("available".into(), json!(unavailable.is_none()));
    if let Some(reason) = unavailable {
        report.insert("reason".into(), json!(reason));
    }
    report.insert("requested".into(), json!(resolved.len() + unidentified));
    report.insert("minted".into(), json!(minted));
    report.insert("not_minted".into(), JsonValue::Array(not_minted));
    if unidentified > 0 {
        report.insert("without_a_usable_id".into(), json!(unidentified));
    }
    output.insert(ACTION_LINKS_REPORT.into(), JsonValue::Object(report));
    JsonValue::Object(output)
}

/// Read a node's `targets` configuration: an object of name → workflow id.
/// Entries with an unusable name or an id that is not a UUID are dropped,
/// and at most [`MAX_ACTION_TARGETS`] are kept (by name order), so a
/// hand-written graph cannot configure an unbounded set.
#[must_use]
pub fn parse_action_targets(raw: Option<&JsonValue>) -> BTreeMap<String, Uuid> {
    let mut targets = BTreeMap::new();
    let Some(map) = raw.and_then(JsonValue::as_object) else {
        return targets;
    };
    let mut names: Vec<&String> = map.keys().collect();
    names.sort();
    for name in names {
        if targets.len() >= MAX_ACTION_TARGETS {
            break;
        }
        if !action_name_valid(name) {
            continue;
        }
        if let Some(id) = map[name].as_str().and_then(|s| Uuid::parse_str(s).ok()) {
            targets.insert(name.clone(), id);
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets() -> BTreeMap<String, Uuid> {
        BTreeMap::from([
            ("list".to_string(), Uuid::from_u128(1)),
            ("bills".to_string(), Uuid::from_u128(2)),
        ])
    }

    fn request(id: &str, target: &str) -> JsonValue {
        json!({ "id": id, "target": target, "label": format!("Do {id}"), "payload": {"id": id} })
    }

    #[test]
    fn a_module_names_a_target_and_never_a_workflow() {
        let foreign = Uuid::from_u128(99).to_string();
        let input = json!({ ACTION_LINKS_REQUEST: [
            request("a", "list"),
            request("b", "nowhere"),
            // A workflow id where a target name belongs is just an unknown name.
            { "id": "c", "target": foreign, "label": "x", "payload": {} },
            // A request that tries to carry its own workflow id is still
            // resolved by `target` alone.
            { "id": "d", "target": "bills", "workflow_id": foreign, "label": "x", "payload": {} },
        ]});
        let (planned, unidentified) = plan_action_links(&input, &targets());
        assert_eq!(unidentified, 0);
        assert_eq!(
            planned[0].spec.as_ref().unwrap().workflow_id,
            Uuid::from_u128(1)
        );
        assert_eq!(planned[1].spec, Err("unknown_target"));
        assert_eq!(planned[2].spec, Err("unknown_target"));
        assert_eq!(
            planned[3].spec.as_ref().unwrap().workflow_id,
            Uuid::from_u128(2)
        );
    }

    #[test]
    fn requests_are_bounded_deduplicated_and_counted() {
        let mut requests: Vec<JsonValue> = (0..MAX_ACTION_LINKS + 3)
            .map(|n| request(&format!("r{n}"), "list"))
            .collect();
        requests.push(request("r0", "bills")); // repeated id: the first stands
        requests.push(json!({ "target": "list" })); // no id
        requests.push(json!({ "id": "has space", "target": "list" })); // unusable id
        let (planned, unidentified) =
            plan_action_links(&json!({ ACTION_LINKS_REQUEST: requests }), &targets());
        assert_eq!(unidentified, 2);
        assert_eq!(planned.len(), MAX_ACTION_LINKS + 3);
        assert_eq!(
            planned.iter().filter(|p| p.spec.is_ok()).count(),
            MAX_ACTION_LINKS
        );
        assert_eq!(
            planned
                .iter()
                .filter(|p| p.spec == Err("too_many_links"))
                .count(),
            3
        );
        assert_eq!(
            planned[0].spec.as_ref().unwrap().workflow_id,
            Uuid::from_u128(1)
        );
        // No requests at all is not an error.
        assert_eq!(
            plan_action_links(&json!({"html": "x"}), &targets()),
            (vec![], 0)
        );
    }

    #[test]
    fn placeholders_are_replaced_everywhere_and_the_request_never_survives() {
        let input = json!({
            "subject": "Morning",
            "html": "<a href=\"talos-action:done-1\">1</a> <a href=\"talos-action:done-12\">12</a> \
                     <a href=\"talos-action:keep-3\">k</a> <a href=\"talos-action:drop-4\">d</a>",
            "parts": [{"text": "see talos-action:done-12"}],
            ACTION_LINKS_REQUEST: [{"id": "done-1"}],
            // A module cannot author the report.
            ACTION_LINKS_REPORT: {"available": true, "minted": 999},
        });
        let resolved = vec![
            ResolvedLink {
                id: "done-1".into(),
                url: Some("https://t.example/action-links/A".into()),
                fallback: None,
                refused: None,
            },
            ResolvedLink {
                id: "done-12".into(),
                url: Some("https://t.example/action-links/B".into()),
                fallback: None,
                refused: None,
            },
            ResolvedLink {
                id: "keep-3".into(),
                url: None,
                fallback: Some("mailto:x@example.com?subject=keep%203".into()),
                refused: Some("unknown_target".into()),
            },
            ResolvedLink {
                id: "drop-4".into(),
                url: None,
                fallback: None,
                refused: Some("workflow_not_owned".into()),
            },
        ];
        let out = apply_action_links(input, &resolved, 1, None);
        let html = out["html"].as_str().unwrap();
        assert!(
            html.contains("href=\"https://t.example/action-links/A\">1<"),
            "{html}"
        );
        // The longer id is not rewritten by the shorter one's replacement.
        assert!(
            html.contains("href=\"https://t.example/action-links/B\">12<"),
            "{html}"
        );
        assert!(
            html.contains("href=\"mailto:x@example.com?subject=keep%203\">k<"),
            "{html}"
        );
        assert!(html.contains("href=\"#\">d<"), "{html}");
        assert!(!html.contains(ACTION_PLACEHOLDER_PREFIX));
        assert_eq!(
            out["parts"][0]["text"],
            "see https://t.example/action-links/B"
        );
        assert!(out.get(ACTION_LINKS_REQUEST).is_none());

        let report = &out[ACTION_LINKS_REPORT];
        assert_eq!(report["available"], true);
        assert_eq!(report["requested"], 5);
        assert_eq!(report["minted"], 2);
        assert_eq!(report["without_a_usable_id"], 1);
        assert_eq!(
            report["not_minted"],
            json!([
                {"id": "keep-3", "reason": "unknown_target", "fell_back": true},
                {"id": "drop-4", "reason": "workflow_not_owned", "fell_back": false},
            ])
        );
    }

    #[test]
    fn when_nothing_can_be_minted_every_link_falls_back_and_the_report_says_why() {
        let input = json!({
            "html": "<a href=\"talos-action:a\">a</a>",
            ACTION_LINKS_REQUEST: [{"id": "a"}],
        });
        let resolved = vec![ResolvedLink {
            id: "a".into(),
            url: None,
            fallback: Some("mailto:x@example.com".into()),
            refused: Some("unavailable".into()),
        }];
        let out = apply_action_links(input, &resolved, 0, Some("link store unavailable"));
        assert_eq!(out["html"], "<a href=\"mailto:x@example.com\">a</a>");
        assert_eq!(out[ACTION_LINKS_REPORT]["available"], false);
        assert_eq!(out[ACTION_LINKS_REPORT]["reason"], "link store unavailable");
        assert_eq!(out[ACTION_LINKS_REPORT]["minted"], 0);
        assert!(out.get(ACTION_LINKS_REQUEST).is_none());
        // A non-object input passes through untouched.
        assert_eq!(
            apply_action_links(json!("text"), &[], 0, None),
            json!("text")
        );
    }

    #[test]
    fn a_fallback_is_a_bounded_mailto_or_https_link_and_nothing_else() {
        assert!(acceptable_fallback("mailto:me+todo@example.com?subject=done%2012").is_some());
        assert!(acceptable_fallback("https://calendar.example/render?x=1").is_some());
        for refused in [
            "javascript:alert(1)",
            "http://insecure.example/",
            "data:text/html,x",
            "https://x.example/\" onclick=\"y",
            "https://x.example/a b",
            "mailto:a@example.com\r\nBcc: b@example.com",
            "",
        ] {
            assert_eq!(acceptable_fallback(refused), None, "{refused:?}");
        }
        let long = format!("https://x.example/{}", "a".repeat(MAX_FALLBACK_CHARS));
        assert_eq!(acceptable_fallback(&long), None);
    }

    #[test]
    fn targets_are_names_to_workflow_ids_and_bounded() {
        let id = Uuid::from_u128(7);
        let parsed = parse_action_targets(Some(&json!({
            "list": id.to_string(),
            "bad name": id.to_string(),
            "not-a-uuid": "pa-list-capture",
            "number": 5,
        })));
        assert_eq!(parsed, BTreeMap::from([("list".to_string(), id)]));
        assert!(parse_action_targets(None).is_empty());
        assert!(parse_action_targets(Some(&json!(["list"]))).is_empty());

        let many: Map<String, JsonValue> = (0..MAX_ACTION_TARGETS + 9)
            .map(|n| (format!("t{n:02}"), json!(id.to_string())))
            .collect();
        assert_eq!(
            parse_action_targets(Some(&JsonValue::Object(many))).len(),
            MAX_ACTION_TARGETS
        );
    }
}
