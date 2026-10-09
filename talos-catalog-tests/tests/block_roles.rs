//! Every catalog template is ONE building block of ONE role
//! (docs/building-blocks.md), declared in its manifest as
//! `"block": {"role": …, "contract"?: …, "reads_by_post"?: "<why>"}`, and
//! the role it declares is held against the grants it asks for. A manifest
//! is what an installer reads to decide whether to trust a module, so this
//! is checked on the manifest, not on the source.
//!
//! The rules, per role:
//! * reader   — reaches one service and changes nothing there: verbs are
//!              GET/HEAD only, or also POST when `reads_by_post` says why;
//!              never PUT/PATCH/DELETE; nothing needs an approval.
//! * sender   — the one place an effect leaves the platform: declares at
//!              least one verb beyond GET/HEAD and a boolean `DRY_RUN` that
//!              sends nothing.
//! * decider  — pure computation over its input (a model through the host's
//!   keeper     llm interface, not HTTP): no host, no verb.
//!   composer
//! * keeper   — additionally the agent-node world: it is the one writer of
//!              its memory key.
//! * composer — additionally minimal-node or agent-node.
//!
//! A `contract` names the shared shape the block reads or returns, and is
//! carried by the matching kind of block only: `notification` by `notify-*`
//! senders, `home-control` by `control-*` senders, `captured` by
//! `capture-*` readers. Every template with one of those prefixes declares
//! its contract.
//!
//! Templates written before the standard (2026-10-09) are listed in
//! UNDECLARED. The list only shrinks: a template that declares a role must
//! come off it, and a template not on it must declare one.

use serde_json::Value;
use std::path::{Path, PathBuf};

const ROLES: &[&str] = &["reader", "decider", "keeper", "composer", "sender"];
const BLOCK_KEYS: &[&str] = &["role", "contract", "reads_by_post"];
/// (contract, slug prefix, role)
const CONTRACTS: &[(&str, &str, &str)] = &[
    ("notification", "notify-", "sender"),
    ("home-control", "control-", "sender"),
    ("captured", "capture-", "reader"),
];
const NETWORK_WORLDS: &[&str] = &[
    "http-node",
    "network-node",
    "messaging-node",
    "automation-node",
];

/// Written before the standard. Remove a slug when its manifest declares a
/// role; never add one.
const UNDECLARED: &[&str] = &[
    "alert-normalize-email",
    "alert-normalize-gcp-monitoring",
    "anthropic-claude",
    "beehiiv-add-to-automation",
    "beehiiv-create-post",
    "beehiiv-get-post-stats",
    "beehiiv-get-referral-program",
    "beehiiv-get-subscriber",
    "beehiiv-list-premium-tiers",
    "beehiiv-list-subscribers",
    "beehiiv-subscribe",
    "beehiiv-update-subscriber",
    "briefing-html-generator",
    "constitutional-refinement",
    "create-calendar-event",
    "csv-parser",
    "data-pipeline-etl",
    "data-validator",
    "database-query",
    "echo-debug",
    "file-transform",
    "gcp-create-monitoring-channel",
    "gcp-create-pubsub-topic",
    "gcp-create-push-subscription",
    "gcp-list-projects",
    "gcp-run-execution-poll",
    "gcp-run-job-execute",
    "gcp-run-logs-fetch",
    "github-analyzer",
    "github-analyzer-public",
    "github-pr-reviewer",
    "google-calendar-webhook",
    "google-mail-webhook",
    "hmac-signer",
    "html-to-text",
    "http-request",
    "http-retry",
    "human-approval",
    "human-review-gate",
    "hybrid-classify-alerts",
    "hybrid-classify-inbox",
    "jira-search-issues",
    "json-transform",
    "jwt-validator",
    "memory-writer",
    "message-publisher",
    "mock-responder",
    "model-predict",
    "multi-agent-router",
    "network-scanner",
    "pagerduty-alert",
    "pii-scrubber",
    "rag-pipeline",
    "redis-cache",
    "send-gmail",
    "send-slack-message",
    "send-teams-message",
    "slack-webhook-listener",
    "smart-classifier",
    "stripe-cancel-subscription",
    "stripe-create-checkout-session",
    "stripe-create-customer",
    "stripe-create-refund",
    "stripe-create-subscription",
    "stripe-get-customer",
    "text-analyzer",
    "webhook-fanout",
    "webhook-to-slack",
    "workflow-assert",
];

fn templates() -> Vec<(String, Value)> {
    let root: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("../module-templates");
    let mut out: Vec<(String, Value)> = std::fs::read_dir(&root)
        .expect("module-templates")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("talos.json").is_file())
        .map(|e| {
            let slug = e.file_name().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(e.path().join("talos.json")).unwrap();
            let manifest: Value =
                serde_json::from_str(&text).unwrap_or_else(|err| panic!("{slug}: {err}"));
            (slug, manifest)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(out.len() > 50, "found only {} templates", out.len());
    out
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(|s| s.trim().to_ascii_uppercase())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn every_template_declares_its_role_unless_it_predates_the_standard() {
    for (slug, m) in templates() {
        let declared = m.get("block").is_some();
        let listed = UNDECLARED.contains(&slug.as_str());
        assert!(
            declared || listed,
            "{slug}: a new template declares its block role (docs/building-blocks.md)"
        );
        assert!(
            !(declared && listed),
            "{slug} declares a role: take it off UNDECLARED"
        );
    }
    // A slug on the list that no longer exists is stale.
    let present: Vec<String> = templates().into_iter().map(|(s, _)| s).collect();
    for slug in UNDECLARED {
        assert!(
            present.iter().any(|p| p == slug),
            "{slug} is on UNDECLARED but is not a template"
        );
    }
}

/// Why a declared role does not fit the manifest, or None.
fn misfit(slug: &str, m: &Value) -> Option<String> {
    let block = m.get("block")?;
    let Some(obj) = block.as_object() else {
        return Some("`block` is not an object".into());
    };
    if let Some(k) = obj.keys().find(|k| !BLOCK_KEYS.contains(&k.as_str())) {
        return Some(format!("`block` has an unknown key `{k}`"));
    }
    let role = obj.get("role").and_then(Value::as_str).unwrap_or("");
    if !ROLES.contains(&role) {
        return Some(format!("role `{role}` is not one of {ROLES:?}"));
    }
    let world = m
        .get("capability_world")
        .and_then(Value::as_str)
        .unwrap_or("");
    let verbs = strings(m.get("allowed_methods"));
    let hosts = strings(m.get("allowed_hosts"));
    let by_post = obj
        .get("reads_by_post")
        .map(|v| v.as_str().map(str::trim).unwrap_or(""));
    if by_post == Some("") {
        return Some("`reads_by_post` must say why the service reads by POST".into());
    }
    if by_post.is_some() && role != "reader" {
        return Some("only a reader declares `reads_by_post`".into());
    }
    let dry_run = m
        .pointer("/config_schema/properties/DRY_RUN/type")
        .and_then(Value::as_str)
        == Some("boolean");
    let reads = |v: &String| v == "GET" || v == "HEAD";
    match role {
        "reader" => {
            if verbs.is_empty() {
                return Some("a reader declares its verbs".into());
            }
            if let Some(v) = verbs
                .iter()
                .find(|v| !reads(v) && !(v.as_str() == "POST" && by_post.is_some()))
            {
                return Some(format!(
                    "a reader does not use {v} (POST only with `reads_by_post`)"
                ));
            }
            if !strings(m.get("requires_approval_for")).is_empty() {
                return Some("a reader needs no approval: it changes nothing".into());
            }
        }
        "sender" => {
            if verbs.is_empty() || verbs.iter().all(reads) {
                return Some(
                    "a sender declares a verb that changes something; GET/HEAD only is a reader"
                        .into(),
                );
            }
            if !dry_run {
                return Some("a sender takes a boolean DRY_RUN that sends nothing".into());
            }
        }
        _ => {
            if !hosts.is_empty() || !verbs.is_empty() || NETWORK_WORLDS.contains(&world) {
                return Some(format!(
                    "a {role} reaches no network: no host, no verb, not {world}"
                ));
            }
            let worlds: &[&str] = match role {
                "keeper" => &["agent-node"],
                "composer" => &["minimal-node", "agent-node"],
                _ => &["minimal-node", "secrets-node", "agent-node"],
            };
            if !worlds.contains(&world) {
                return Some(format!("a {role} runs in {worlds:?}, not {world}"));
            }
        }
    }
    let contract = obj.get("contract").and_then(Value::as_str);
    for (name, prefix, want) in CONTRACTS {
        let named = contract == Some(*name);
        if named && (!slug.starts_with(prefix) || role != *want) {
            return Some(format!(
                "the {name} contract is carried by a `{prefix}*` {want}"
            ));
        }
        if slug.starts_with(prefix) && !named {
            return Some(format!(
                "a `{prefix}*` template declares the {name} contract"
            ));
        }
    }
    if let Some(c) = contract.filter(|c| !CONTRACTS.iter().any(|(n, _, _)| n == c)) {
        return Some(format!("unknown contract `{c}`"));
    }
    None
}

#[test]
fn every_declared_role_fits_the_grants_its_manifest_asks_for() {
    let wrong: Vec<String> = templates()
        .iter()
        .filter_map(|(slug, m)| misfit(slug, m).map(|why| format!("{slug}: {why}")))
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    // The rules are not vacuous: enough templates are held to them.
    let declared = templates()
        .iter()
        .filter(|(_, m)| m.get("block").is_some())
        .count();
    assert!(declared >= 17, "only {declared} templates declare a role");
}

#[test]
fn the_rules_refuse_what_they_are_for() {
    let j = |s: &str| -> Value { serde_json::from_str(s).unwrap() };
    let base = r#"{"capability_world":"http-node","allowed_hosts":[],"allowed_methods":["GET"],"requires_approval_for":[],
                   "config_schema":{"properties":{}},"block":{"role":"reader"}}"#;
    assert_eq!(misfit("a-reader", &j(base)), None);
    let cases: &[(&str, &str, &str)] = &[
        (
            "a-reader",
            r#""allowed_methods":["GET"]"#,
            r#""allowed_methods":["GET","DELETE"]"#,
        ),
        (
            "a-reader",
            r#""allowed_methods":["GET"]"#,
            r#""allowed_methods":["POST"]"#,
        ),
        (
            "a-reader",
            r#""requires_approval_for":[]"#,
            r#""requires_approval_for":["POST"]"#,
        ),
        ("a-reader", r#""role":"reader""#, r#""role":"sender""#),
        ("a-reader", r#""role":"reader""#, r#""role":"composer""#),
        ("a-reader", r#""role":"reader""#, r#""role":"fetcher""#),
        (
            "a-reader",
            r#""role":"reader""#,
            r#""role":"reader","reads_by_post":"""#,
        ),
        (
            "a-reader",
            r#""role":"reader""#,
            r#""role":"reader","contract":"captured""#,
        ),
        (
            "a-reader",
            r#""role":"reader""#,
            r#""role":"reader","contract":"made-up""#,
        ),
        (
            "a-reader",
            r#""role":"reader""#,
            r#""role":"reader","typo":1"#,
        ),
        ("capture-x", r#""role":"reader""#, r#""role":"reader""#),
        (
            "notify-x",
            r#""role":"reader""#,
            r#""role":"sender","contract":"notification""#,
        ),
    ];
    for (slug, from, to) in cases {
        assert!(base.contains(from), "{from}");
        let m = j(&base.replace(from, to));
        assert!(misfit(slug, &m).is_some(), "{slug} with {to} was accepted");
    }
    // A sender is refused without DRY_RUN and accepted with it.
    let sender = base
        .replace(
            r#""allowed_methods":["GET"]"#,
            r#""allowed_methods":["POST"]"#,
        )
        .replace(r#""role":"reader""#, r#""role":"sender""#);
    assert!(misfit("a-sender", &j(&sender)).is_some());
    let sender = sender.replace(
        r#""properties":{}"#,
        r#""properties":{"DRY_RUN":{"type":"boolean"}}"#,
    );
    assert_eq!(misfit("a-sender", &j(&sender)), None);
    // A decider reaches no network, and a keeper is agent-node.
    let decider = base
        .replace(r#""allowed_methods":["GET"]"#, r#""allowed_methods":[]"#)
        .replace(r#""role":"reader""#, r#""role":"decider""#)
        .replace("http-node", "minimal-node");
    assert_eq!(misfit("a-decider", &j(&decider)), None);
    assert!(misfit(
        "a-decider",
        &j(&decider.replace(
            r#""allowed_hosts":[]"#,
            r#""allowed_hosts":["api.example.test"]"#
        ))
    )
    .is_some());
    assert!(misfit(
        "a-keeper",
        &j(&decider.replace(r#""role":"decider""#, r#""role":"keeper""#))
    )
    .is_some());
    assert_eq!(
        misfit(
            "a-keeper",
            &j(&decider
                .replace(r#""role":"decider""#, r#""role":"keeper""#)
                .replace("minimal-node", "agent-node"))
        ),
        None
    );
}
