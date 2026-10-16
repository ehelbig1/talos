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
                "kept_actions",
                "link_dropped",
                "link_sent",
                "one_tap_actions",
                "parts_sent",
                "parts_total",
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
        // One notification is a list of one.
        assert_eq!(
            (v["parts_total"].clone(), v["parts_sent"].clone()),
            (json!(1), json!(1)),
            "{}",
            adapter.slug
        );
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

/// The engine records a sent message by reading the adapter's verdict
/// (`talos_workflow_engine_core::delivery_verdict`). This holds the reader to
/// the real verdict every adapter returns: a send reads as the send it was,
/// and a skip or a dry run reads as nothing sent.
#[test]
fn the_engine_reads_every_adapters_verdict_as_the_send_it_was() {
    use talos_workflow_engine_core::delivery_verdict::{read_delivery_verdict, DeliveryReading};

    let full = json!({ "notification": {
        "title": "Morning", "body": "Three things today.",
        "actions": [
            { "title": "Done", "link": "https://talos.example.test/action-links/aaaa", "one_tap": true, "keep": true },
            { "title": "Open", "link": "https://talos.example.test/list" },
        ] } });
    for adapter in ADAPTERS {
        let sent =
            deliver(adapter, full.clone()).unwrap_or_else(|e| panic!("{}: {e}", adapter.slug));
        let _ = host::http::requests();
        match read_delivery_verdict(&sent) {
            DeliveryReading::Sent(d) => {
                assert_eq!(
                    (
                        d.parts_total,
                        d.parts_sent,
                        d.actions_sent,
                        d.one_tap_actions
                    ),
                    (1, 1, 2, u32::from(adapter.one_tap)),
                    "{}: {sent}",
                    adapter.slug
                );
                assert!(d.kept_actions <= d.actions_sent, "{}: {sent}", adapter.slug);
                assert!(!d.provider.is_empty(), "{}", adapter.slug);
            }
            other => panic!("{}: a send read as {other:?}: {sent}", adapter.slug),
        }

        let skipped = deliver(adapter, json!({ "skip": true })).unwrap();
        assert_eq!(
            read_delivery_verdict(&skipped),
            DeliveryReading::NothingSent,
            "{}: {skipped}",
            adapter.slug
        );

        let mut dry = full.clone();
        dry["config"] = (adapter.config)();
        dry["config"]["DRY_RUN"] = json!(true);
        host::http::respond(200, "{}");
        let dry: Value = (adapter.run)(dry.to_string())
            .map(|s| serde_json::from_str(&s).expect("a JSON verdict"))
            .unwrap_or_else(|e| panic!("{}: {e}", adapter.slug));
        let _ = host::http::requests();
        assert_eq!(
            read_delivery_verdict(&dry),
            DeliveryReading::NothingSent,
            "{}: a dry run read as a send: {dry}",
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

// ── several notifications in order (2026-10-13) ────────────────────────────

fn part(n: usize, actions: Value) -> Value {
    json!({ "title": format!("Part {n}"), "body": format!("the text of part {n}"), "actions": actions })
}

/// Three parts; the last carries the buttons, as a composer writes them.
fn three_parts() -> Value {
    json!({ "notifications": [
        part(1, json!([])),
        part(2, json!([])),
        part(3, json!([
            { "title": "Post", "link": "https://talos.example.test/action-links/aaaa", "one_tap": true, "keep": true },
            { "title": "Tick", "link": "https://talos.example.test/action-links/bbbb", "one_tap": true },
        ])),
    ]})
}

/// Run `adapter` on `upstream`, answering request N (from 1) with
/// `status_for(N)`. Returns the verdict or the error, and the bodies sent.
fn deliver_scripted(
    adapter: &Adapter,
    upstream: Value,
    status_for: fn(usize) -> u16,
) -> (Result<Value, String>, Vec<String>) {
    let before = host::http::requests().len();
    let mut seen = 0usize;
    host::http::respond_with(move |_| {
        seen += 1;
        Ok(host::http::response(status_for(seen), "{}"))
    });
    let mut input = upstream;
    input["config"] = (adapter.config)();
    let outcome =
        (adapter.run)(input.to_string()).map(|s| serde_json::from_str(&s).expect("a JSON verdict"));
    let sent = host::http::requests()[before..]
        .iter()
        .map(|r| String::from_utf8(r.body.clone()).unwrap())
        .collect();
    (outcome, sent)
}

#[test]
fn a_list_is_delivered_in_order_one_request_each_by_every_adapter() {
    for adapter in ADAPTERS {
        let (verdict, sent) = deliver_scripted(adapter, three_parts(), |_| 200);
        let v = verdict.unwrap_or_else(|e| panic!("{}: {e}", adapter.slug));
        assert_eq!(sent.len(), 3, "{}: one request per part", adapter.slug);
        for (index, body) in sent.iter().enumerate() {
            assert!(
                body.contains(&format!("the text of part {}", index + 1)),
                "{}: request {} is not part {}: {body}",
                adapter.slug,
                index + 1,
                index + 1
            );
        }
        // The buttons travel with the last part and no other.
        assert!(!sent[0].contains("action-links") && !sent[1].contains("action-links"));
        assert!(sent[2].contains("action-links/aaaa") && sent[2].contains("action-links/bbbb"));

        assert_eq!(v["sent"], json!(true), "{}", adapter.slug);
        assert_eq!(
            (v["parts_total"].clone(), v["parts_sent"].clone()),
            (json!(3), json!(3)),
            "{}",
            adapter.slug
        );
        // Counts are sums across the parts.
        assert_eq!(v["actions_sent"], json!(2), "{}", adapter.slug);
        assert_eq!(
            v["one_tap_actions"],
            json!(if adapter.one_tap { 2 } else { 0 }),
            "{}",
            adapter.slug
        );
        // Keeping the notification after an action is used is something a
        // service can or cannot do; like one_tap, it is reported.
        assert_eq!(
            v["kept_actions"],
            json!(u8::from(adapter.one_tap)),
            "{}",
            adapter.slug
        );
    }
}

#[test]
fn a_part_that_fails_stops_the_rest_and_fails_the_node_saying_how_far_it_got() {
    for adapter in ADAPTERS {
        let (verdict, sent) =
            deliver_scripted(adapter, three_parts(), |n| if n == 2 { 500 } else { 200 });
        let error = verdict.expect_err("a failed part fails the node");
        assert_eq!(
            sent.len(),
            2,
            "{}: the part after the failure was sent anyway",
            adapter.slug
        );
        assert!(
            error.contains("notification 2 of 3 was not delivered")
                && error.contains("answered 500"),
            "{}: {error}",
            adapter.slug
        );
        assert!(
            error.contains("1 delivered before it, none after"),
            "{}: {error}",
            adapter.slug
        );
        assert!(
            error.contains("Do not retry this node"),
            "{}: {error}",
            adapter.slug
        );

        // The buttons were in the part that was never sent.
        assert!(sent.iter().all(|body| !body.contains("action-links")));

        // One notification fails with the adapter's own words, as before.
        let one = json!({ "notification": { "body": "b" } });
        let (verdict, _) = deliver_scripted(adapter, one, |_| 503);
        let error = verdict.unwrap_err();
        assert!(error.ends_with("answered 503"), "{}: {error}", adapter.slug);
        assert!(!error.contains("of 1"), "{}: {error}", adapter.slug);
    }
}

#[test]
fn a_list_is_bounded_and_refused_whole_before_anything_is_sent() {
    let seven: Vec<Value> = (1..=7).map(|n| part(n, json!([]))).collect();
    let six: Vec<Value> = (1..=6).map(|n| part(n, json!([]))).collect();
    for adapter in ADAPTERS {
        let before = host::http::requests().len();
        for (upstream, why) in [
            (
                json!({ "notifications": [] }),
                "1 to 6 notifications; got 0",
            ),
            (
                json!({ "notifications": seven }),
                "1 to 6 notifications; got 7",
            ),
            (
                json!({ "notification": { "body": "b" }, "notifications": [{ "body": "b" }] }),
                "not both",
            ),
            // One bad part refuses the list: half a message is not what was
            // composed.
            (
                json!({ "notifications": [{ "body": "fine" }, { "title": "no body" }] }),
                "notification 2 of 2: The notification has no `body`",
            ),
            (
                json!({ "notifications": [{ "body": "b", "priority": "urgent" }] }),
                "notification 1 of 1",
            ),
        ] {
            let (verdict, _) = deliver_scripted(adapter, upstream.clone(), |_| 200);
            let error = verdict.unwrap_err();
            assert!(error.contains(why), "{}: {upstream}: {error}", adapter.slug);
        }
        assert_eq!(
            host::http::requests().len(),
            before,
            "{}: something was sent for a refused list",
            adapter.slug
        );

        // The most a list may hold is delivered whole.
        let (verdict, sent) = deliver_scripted(adapter, json!({ "notifications": six }), |_| 200);
        assert_eq!(verdict.unwrap()["parts_sent"], json!(6), "{}", adapter.slug);
        assert_eq!(sent.len(), 6);

        // `skip` sends nothing, list or not; a dry run counts and sends nothing.
        let (verdict, sent) = deliver_scripted(
            adapter,
            json!({ "skip": true, "notifications": [{ "body": "b" }] }),
            |_| 200,
        );
        assert_eq!(verdict.unwrap()["skipped"], json!(true));
        assert!(sent.is_empty());
        let mut dry = three_parts();
        let mut config = (adapter.config)();
        config["DRY_RUN"] = json!(true);
        dry["config"] = config;
        let before = host::http::requests().len();
        let v: Value = serde_json::from_str(&(adapter.run)(dry.to_string()).unwrap()).unwrap();
        assert_eq!(
            (
                v["parts_total"].clone(),
                v["parts_sent"].clone(),
                v["sent"].clone()
            ),
            (json!(3), json!(0), json!(false)),
            "{}",
            adapter.slug
        );
        assert_eq!(host::http::requests().len(), before);
    }
}
