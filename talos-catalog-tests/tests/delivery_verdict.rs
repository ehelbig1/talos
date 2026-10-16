//! Every sender of a message returns the delivery verdict, and the engine
//! reads it as the send it was (2026-10-16).
//!
//! The engine records a sent message from the sender's output
//! (`talos_workflow_engine_core::delivery_verdict`, `message_deliveries`):
//! `provider`, `sent`, `parts_total`, `parts_sent` and the action counts. The
//! notification contract fixes that shape for the `notify-*` adapters; the
//! email sender returns the same fields beside its own. A message sender that
//! returned something else would send and never be counted, so every
//! template that is a sender of a message (`notify-*`, `send-*`, role
//! `sender`) is driven here, through its real `run`, and its verdict read
//! through the engine's reader: a send is `Sent` with the provider's word and
//! the action links it carried, and a skip or a dry run is `NothingSent`.
//!
//! Adding a message sender: add it to `SENDERS`.

use serde_json::{json, Value};
use talos_module_testkit::host;
use talos_workflow_engine_core::delivery_verdict::{read_delivery_verdict, DeliveryReading};

struct Sender {
    slug: &'static str,
    run: fn(String) -> Result<String, String>,
    config: fn() -> Value,
    /// An upstream output with exactly one action link in it.
    message: fn() -> Value,
    /// The verdict's word for the service.
    provider: &'static str,
}

const ACTION_LINK: &str = "https://talos.example.test/action-links/aaaa";

fn notification() -> Value {
    json!({ "notification": { "body": "Done?",
            "actions": [{ "title": "Done", "link": ACTION_LINK }] } })
}

const SENDERS: &[Sender] = &[
    Sender {
        slug: "notify-ntfy",
        run: talos_catalog_tests::notify_ntfy::run,
        config: || json!({ "SERVER_URL": "https://ntfy.example.test", "TOPIC": "made-up-topic" }),
        message: notification,
        provider: "ntfy",
    },
    Sender {
        slug: "notify-home-assistant",
        run: talos_catalog_tests::notify_home_assistant::run,
        config: || {
            json!({ "BASE_URL": "https://home.example.test", "NOTIFY_SERVICE": "mobile_app_made_up_phone",
                    "AUTH_HEADER": "Bearer vault://homeassistant/token" })
        },
        message: notification,
        provider: "home-assistant",
    },
    Sender {
        slug: "send-html-email",
        run: talos_catalog_tests::send_html_email::run,
        config: || json!({ "AUTH_HEADER": "Bearer vault://oauth/gmail/made-up/access_token", "TO": "reader@example.com" }),
        message: || json!({ "subject": "Done?", "html": format!("<p><a href=\"{ACTION_LINK}\">done</a></p>") }),
        provider: "gmail",
    },
];

/// The prefixes a sender of a message is named with.
const MESSAGE_SENDER_PREFIXES: &[&str] = &["notify-", "send-"];

fn manifests() -> Vec<(String, Value)> {
    talos_catalog_tests::template_dirs()
        .into_iter()
        .filter(|dir| dir.join("talos.json").is_file())
        .map(|dir| {
            let slug = dir.file_name().unwrap().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(dir.join("talos.json")).unwrap();
            let manifest: Value =
                serde_json::from_str(&text).unwrap_or_else(|err| panic!("{slug}: {err}"));
            (slug, manifest)
        })
        .collect()
}

fn deliver(sender: &Sender, upstream: Value, dry_run: bool) -> Result<Value, String> {
    host::http::respond(200, r#"{"id":"made-up","threadId":"made-up"}"#);
    let mut input = upstream;
    let mut config = (sender.config)();
    if dry_run {
        config["DRY_RUN"] = json!(true);
    }
    input["config"] = config;
    (sender.run)(input.to_string()).map(|s| serde_json::from_str(&s).expect("a JSON verdict"))
}

#[test]
fn every_message_sender_is_in_the_list() {
    let listed: Vec<&str> = SENDERS.iter().map(|s| s.slug).collect();
    let manifests = manifests();
    for (slug, m) in &manifests {
        let is_sender = m.pointer("/block/role").and_then(Value::as_str) == Some("sender");
        let named_as_one = MESSAGE_SENDER_PREFIXES.iter().any(|p| slug.starts_with(p));
        if is_sender && named_as_one {
            assert!(
                listed.contains(&slug.as_str()),
                "{slug} sends a message: add it to SENDERS so the engine is shown to read its verdict"
            );
        }
    }
    for slug in listed {
        let m = &manifests
            .iter()
            .find(|(s, _)| s == slug)
            .unwrap_or_else(|| panic!("{slug} is in SENDERS but is not a template"))
            .1;
        assert_eq!(
            m.pointer("/block/role").and_then(Value::as_str),
            Some("sender"),
            "{slug} is in SENDERS but does not declare the sender role"
        );
    }
}

#[test]
fn a_send_is_read_as_the_send_it_was_with_the_action_it_carried() {
    for sender in SENDERS {
        let v = deliver(sender, (sender.message)(), false)
            .unwrap_or_else(|e| panic!("{}: {e}", sender.slug));
        match read_delivery_verdict(&v) {
            DeliveryReading::Sent(d) => {
                assert_eq!(d.provider, sender.provider, "{}: {v}", sender.slug);
                assert_eq!(
                    (d.parts_total, d.parts_sent),
                    (1, 1),
                    "{}: {v}",
                    sender.slug
                );
                assert_eq!(d.actions_sent, 1, "{}: {v}", sender.slug);
            }
            other => panic!("{}: the engine read a send as {other:?}: {v}", sender.slug),
        }
    }
}

#[test]
fn a_skip_and_a_dry_run_are_read_as_nothing_sent() {
    for sender in SENDERS {
        let skipped = deliver(sender, json!({ "skip": true }), false)
            .unwrap_or_else(|e| panic!("{}: {e}", sender.slug));
        assert_eq!(
            read_delivery_verdict(&skipped),
            DeliveryReading::NothingSent,
            "{}: a skip: {skipped}",
            sender.slug
        );
        let dry = deliver(sender, (sender.message)(), true)
            .unwrap_or_else(|e| panic!("{}: {e}", sender.slug));
        assert_eq!(
            read_delivery_verdict(&dry),
            DeliveryReading::NothingSent,
            "{}: a dry run: {dry}",
            sender.slug
        );
        // And both still say which service, and that nothing left.
        for (what, v) in [("skip", &skipped), ("dry run", &dry)] {
            assert_eq!(
                v["provider"],
                json!(sender.provider),
                "{}: {what}",
                sender.slug
            );
            assert_eq!(v["sent"], json!(false), "{}: {what}", sender.slug);
            assert_eq!(v["parts_sent"], json!(0), "{}: {what}", sender.slug);
        }
    }
}
