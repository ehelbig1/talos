//! The capture contract: every `capture-*` adapter returns the same neutral
//! `captured` shape (docs/capture-contract.md, 2026-10-09).
//!
//! What keeps captured lines (a list, a journal) must not learn which service
//! they came from, or replacing the service means rewriting the keeper. That
//! holds only while the adapters agree, so this test holds them to it:
//!
//! * the contract block in each adapter's source is byte-identical;
//! * every adapter's output follows the contract's rules for the same kind of
//!   input (duplicates, empty lines, control characters, too many lines);
//! * every adapter installs able to reach nothing, and only to read.
//!
//! Adding an adapter: copy the block, add the adapter to `ADAPTERS`.

use serde_json::{json, Value};
use talos_module_testkit::host;

struct Adapter {
    slug: &'static str,
    run: fn(String) -> Result<String, String>,
    config: fn() -> Value,
    /// Primes the stand-in host with a service answer holding `lines` (text
    /// per line, oldest first; a repeated index is the same line read twice).
    respond: fn(&[(u64, &str)]),
}

const NOW_MS: u64 = 1_791_560_000_000;

const ADAPTERS: &[Adapter] = &[Adapter {
    slug: "capture-home-assistant",
    run: talos_catalog_tests::capture_home_assistant::run,
    config: || {
        json!({ "BASE_URL": "https://home.example.test", "AUTH_HEADER": "Bearer vault://homeassistant/token",
                "ENTITY": "input_text.made_up_capture", "NOW_MS": NOW_MS })
    },
    respond: |lines| {
        let rows: Vec<Value> = lines
            .iter()
            .map(
                |(n, text)| json!({ "state": format!("{}|{text}", NOW_MS - 3_600_000 + n * 1000) }),
            )
            .collect();
        host::http::respond(200, json!([rows]).to_string());
    },
}];

const BEGIN: &str = "// ── capture contract ──";
const END: &str = "// ── end capture contract ──";
const MAX_LINES: usize = 20;
const MAX_TEXT_CHARS: usize = 240;

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
        .unwrap_or_else(|| panic!("{slug}: no capture contract block"));
    let end = source[start..]
        .find(END)
        .unwrap_or_else(|| panic!("{slug}: the contract block is not closed"));
    source[start..start + end].to_string()
}

#[test]
fn every_adapter_carries_the_same_contract_block() {
    let first = contract_block(ADAPTERS[0].slug);
    assert!(first.len() > 1500, "the block is suspiciously short");
    assert!(
        first.contains("fn captured_output("),
        "the block builds the output"
    );
    for adapter in &ADAPTERS[1..] {
        assert!(
            contract_block(adapter.slug) == first,
            "{} and {} have different capture contract blocks; they must be byte-identical",
            ADAPTERS[0].slug,
            adapter.slug
        );
    }
}

#[test]
fn every_capture_template_is_in_the_adapter_list() {
    let mut found: Vec<String> = std::fs::read_dir(template_dir("."))
        .expect("module-templates")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("capture-"))
        .collect();
    found.sort();
    let mut listed: Vec<&str> = ADAPTERS.iter().map(|a| a.slug).collect();
    listed.sort_unstable();
    assert_eq!(
        found, listed,
        "a capture-* template is not held to the contract"
    );
}

fn capture(adapter: &Adapter, lines: &[(u64, &str)]) -> Value {
    (adapter.respond)(lines);
    let input = json!({ "config": (adapter.config)() });
    let out = (adapter.run)(input.to_string()).unwrap_or_else(|e| panic!("{}: {e}", adapter.slug));
    serde_json::from_str(&out).expect("a JSON output")
}

#[test]
fn every_adapter_returns_the_contract_shape_by_the_contract_rules() {
    let long = "x".repeat(MAX_TEXT_CHARS + 50);
    let mut lines: Vec<(u64, String)> = vec![
        (1, "  buy\tstamps \u{7} today ".to_string()),
        (2, "   ".to_string()),
        (3, long.clone()),
        (1, "buy stamps today".to_string()),
    ];
    for n in 10..10 + MAX_LINES as u64 {
        lines.push((n, format!("line {n}")));
    }
    let borrowed: Vec<(u64, &str)> = lines.iter().map(|(n, t)| (*n, t.as_str())).collect();
    for adapter in ADAPTERS {
        let v = capture(adapter, &borrowed);
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["captured", "count", "ignored", "kind", "source"],
            "{}: the fields are the contract",
            adapter.slug
        );
        assert_eq!(v["kind"], json!("captured"), "{}", adapter.slug);
        let source = v["source"].as_str().unwrap();
        assert!(
            !source.is_empty() && source.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
            "{}",
            adapter.slug
        );

        let captured = v["captured"].as_array().unwrap();
        assert_eq!(v["count"], json!(captured.len()), "{}", adapter.slug);
        assert_eq!(
            captured.len(),
            MAX_LINES,
            "{}: at most {MAX_LINES}, the newest kept",
            adapter.slug
        );
        // 24 offered: the duplicate and the blank line are left out, then the
        // two oldest over the cap.
        assert_eq!(v["ignored"], json!(4), "{}: {v}", adapter.slug);
        assert_eq!(
            captured.last().unwrap()["text"],
            json!(format!("line {}", 9 + MAX_LINES)),
            "{}: oldest first",
            adapter.slug
        );

        let mut ids: Vec<&str> = Vec::new();
        for line in captured {
            let obj = line.as_object().unwrap();
            assert_eq!(
                obj.keys().map(String::as_str).collect::<Vec<_>>(),
                ["id", "text"],
                "{}",
                adapter.slug
            );
            let id = line["id"].as_str().unwrap();
            assert!(
                id.starts_with(&format!("{source}:")) && id.len() > source.len() + 1,
                "{}: {id}",
                adapter.slug
            );
            assert!(!ids.contains(&id), "{}: {id} twice", adapter.slug);
            ids.push(id);
            let text = line["text"].as_str().unwrap();
            assert!(
                !text.is_empty() && text.chars().count() <= MAX_TEXT_CHARS,
                "{}: {text:?}",
                adapter.slug
            );
            assert!(
                !text.chars().any(char::is_control) && !text.contains("  ") && text.trim() == text,
                "{}: {text:?}",
                adapter.slug
            );
        }

        // The same answer read twice is the same output: ids are stable.
        assert_eq!(capture(adapter, &borrowed), v, "{}", adapter.slug);
        // Nothing typed is an empty answer, not an error.
        let empty = capture(adapter, &[]);
        assert_eq!(
            (empty["count"].clone(), empty["captured"].clone()),
            (json!(0), json!([])),
            "{}",
            adapter.slug
        );
    }
}

#[test]
fn the_cut_and_the_clean_up_are_the_same_in_every_adapter() {
    for adapter in ADAPTERS {
        let long = "é".repeat(MAX_TEXT_CHARS + 10);
        let v = capture(adapter, &[(1, "  buy\tstamps \u{7} today "), (2, &long)]);
        assert_eq!(
            v["captured"][0]["text"],
            json!("buy stamps today"),
            "{}",
            adapter.slug
        );
        assert_eq!(
            v["captured"][1]["text"].as_str().unwrap().chars().count(),
            MAX_TEXT_CHARS,
            "{}",
            adapter.slug
        );
    }
}

#[test]
fn every_adapter_installs_able_to_reach_nothing_and_only_to_read() {
    for adapter in ADAPTERS {
        let text = std::fs::read_to_string(template_dir(adapter.slug).join("talos.json")).unwrap();
        let m: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            m["allowed_hosts"],
            json!([]),
            "{}: the installer names the host",
            adapter.slug
        );
        assert_eq!(
            m["requires_secrets"],
            json!([]),
            "{}: the installer names the secret",
            adapter.slug
        );
        assert_eq!(
            m["allowed_methods"],
            json!(["GET"]),
            "{}: a capture adapter only reads",
            adapter.slug
        );
        assert_eq!(
            m["block"],
            json!({ "role": "reader", "contract": "captured" }),
            "{}",
            adapter.slug
        );
    }
}
