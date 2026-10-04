//! The notification contract: every `notify-*` adapter reads the same
//! `notification` and returns the same verdict (2026-10-04).
//!
//! The point of the contract is that a delivery service can be replaced
//! without touching what composes the message. That holds only while the
//! adapters agree, so this test holds them to it three ways:
//!
//! * the contract block in each adapter's source is byte-identical;
//! * given the same documents, every adapter returns the same verdict in
//!   every field the contract defines as service-independent;
//! * every adapter has a catalog manifest that installs with no host and no
//!   secret, and only POST.
//!
//! Adding an adapter: copy the block, add the adapter to `ADAPTERS`.

use serde_json::{json, Value};
use talos_module_testkit::host;

struct Adapter {
    slug: &'static str,
    run: fn(String) -> Result<String, String>,
    config: fn() -> Value,
    /// Whether the service can act on an action in the background.
    one_tap: bool,
    /// Whether the service replaces an earlier message with the same tag.
    tag: bool,
}

const ADAPTERS: &[Adapter] = &[
    Adapter {
        slug: "notify-ntfy",
        run: talos_catalog_tests::notify_ntfy::run,
        config: || json!({ "SERVER_URL": "https://ntfy.example.test", "TOPIC": "made-up-topic" }),
        one_tap: true,
        tag: false,
    },
    Adapter {
        slug: "notify-home-assistant",
        run: talos_catalog_tests::notify_home_assistant::run,
        config: || {
            json!({ "BASE_URL": "https://home.example.test", "NOTIFY_SERVICE": "mobile_app_made_up_phone",
                    "AUTH_HEADER": "Bearer vault://homeassistant/token" })
        },
        one_tap: false,
        tag: true,
    },
];

const BEGIN: &str = "// ── notification contract ──";
const END: &str = "// ── end notification contract ──";

fn template_dir(slug: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../module-templates")
        .join(slug)
}

fn contract_block(slug: &str) -> String {
    let source = std::fs::read_to_string(template_dir(slug).join("template.rs"))
        .unwrap_or_else(|e| panic!("{slug}: {e}"));
    let start = source
        .find(BEGIN)
        .unwrap_or_else(|| panic!("{slug}: no contract block"));
    let end = source[start..]
        .find(END)
        .unwrap_or_else(|| panic!("{slug}: the contract block is not closed"));
    source[start..start + end].to_string()
}

#[test]
fn every_adapter_carries_the_same_contract_block() {
    let first = contract_block(ADAPTERS[0].slug);
    assert!(first.len() > 2000, "the block is suspiciously short");
    for adapter in &ADAPTERS[1..] {
        assert!(
            contract_block(adapter.slug) == first,
            "{} and {} have different notification contract blocks; they must be byte-identical",
            ADAPTERS[0].slug,
            adapter.slug
        );
    }
}

#[test]
fn every_notify_template_is_in_the_adapter_list() {
    let mut found: Vec<String> = std::fs::read_dir(template_dir("."))
        .expect("module-templates")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("notify-"))
        .collect();
    found.sort();
    let mut listed: Vec<&str> = ADAPTERS.iter().map(|a| a.slug).collect();
    listed.sort_unstable();
    assert_eq!(
        found, listed,
        "a notify-* template is not held to the contract"
    );
}

fn deliver(adapter: &Adapter, upstream: Value) -> Result<Value, String> {
    host::http::respond(200, "{}");
    let mut input = upstream;
    input["config"] = (adapter.config)();
    (adapter.run)(input.to_string()).map(|s| serde_json::from_str(&s).expect("a JSON verdict"))
}

#[test]
fn the_same_notification_gets_the_same_verdict_from_every_adapter() {
    let full = json!({ "notification": {
        "title": "Morning", "body": "Three things today.", "priority": "high", "tag": "morning",
        "link": "https://talos.example.test/today",
        "actions": [
            { "title": "Done", "link": "https://talos.example.test/action-links/aaaa", "one_tap": true },
            { "title": "Dead", "link": "#" },
            { "title": "Open", "link": "https://talos.example.test/list" },
        ] } });
    for adapter in ADAPTERS {
        let v = deliver(adapter, full.clone()).unwrap_or_else(|e| panic!("{}: {e}", adapter.slug));
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "actions_dropped",
                "actions_sent",
                "dry_run",
                "link_dropped",
                "link_sent",
                "one_tap_actions",
                "provider",
                "sent",
                "skipped",
                "status",
                "tag_sent"
            ],
            "{}: the verdict's fields are the contract",
            adapter.slug
        );
        assert_eq!(v["sent"], json!(true), "{}", adapter.slug);
        assert_eq!(v["actions_sent"], json!(2), "{}", adapter.slug);
        assert_eq!(v["actions_dropped"], json!(1), "{}", adapter.slug);
        assert_eq!(v["link_sent"], json!(true), "{}", adapter.slug);
        // The two things a service may or may not be able to do are REPORTED,
        // so a workflow can tell which it got.
        assert_eq!(
            v["one_tap_actions"],
            json!(u8::from(adapter.one_tap)),
            "{}",
            adapter.slug
        );
        assert_eq!(v["tag_sent"], json!(adapter.tag), "{}", adapter.slug);
        // The words reach the service whatever it calls its fields.
        let sent =
            String::from_utf8(host::http::requests().pop().expect("a request").body).unwrap();
        assert!(
            sent.contains("Three things today.") && sent.contains("Morning"),
            "{}: {sent}",
            adapter.slug
        );
        assert!(
            !sent.contains("\"#\""),
            "{}: a dead link was sent",
            adapter.slug
        );
    }
}

#[test]
fn every_adapter_refuses_and_skips_alike() {
    for adapter in ADAPTERS {
        let skipped = deliver(adapter, json!({ "skip": true })).unwrap();
        assert_eq!(
            (skipped["skipped"].clone(), skipped["sent"].clone()),
            (json!(true), json!(false)),
            "{}",
            adapter.slug
        );
        for (upstream, why) in [
            (json!({}), "no `notification` object"),
            (
                json!({ "notification": { "title": "only a title" } }),
                "no `body`",
            ),
            (
                json!({ "notification": { "body": "b", "priority": "urgent" } }),
                "low, normal or high",
            ),
        ] {
            let e = deliver(adapter, upstream.clone()).unwrap_err();
            assert!(e.contains(why), "{}: {upstream}: {e}", adapter.slug);
        }
        assert!(
            host::http::requests().is_empty(),
            "{}: something was sent",
            adapter.slug
        );
    }
}

#[test]
fn every_adapter_installs_able_to_reach_nothing() {
    for adapter in ADAPTERS {
        let manifest: Value = serde_json::from_str(
            &std::fs::read_to_string(template_dir(adapter.slug).join("talos.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["allowed_hosts"], json!([]), "{}", adapter.slug);
        assert_eq!(manifest["requires_secrets"], json!([]), "{}", adapter.slug);
        assert_eq!(
            manifest["allowed_methods"],
            json!(["POST"]),
            "{}",
            adapter.slug
        );
        assert_eq!(
            manifest["capability_world"],
            json!("http-node"),
            "{}",
            adapter.slug
        );
    }
}
