// skeleton-composer: renders one surface, a phone notification in the
// service-neutral `notification` shape (docs/notification-contract.md), from
// what a decider decided. It renders; it does not decide. A `notify-*` sender
// delivers it.
//
// TODO(author): say what it renders from which node. Replace the input shape
// (`picked`, as a new decider hands it on) and the wording with yours.
//
// What this shape already does, and what the catalog's tests hold it to:
// * minimal-node: no host, no verb, no memory;
// * every string from its input is made plain (no control characters) and
//   cut to the contract's lengths before it is rendered;
// * when its input is stale (`__staleness__`) or a branch above it failed
//   (`__degraded_inputs__`), the message says so instead of drawing fewer
//   conclusions in silence;
// * nothing to say is `skip: true`, never an empty message.

use serde::Deserialize;
use serde_json::json;
use talos_sdk_macros::talos_module;

const TITLE_CHARS: usize = 120;
const BODY_CHARS: usize = 1500;
const LINE_CHARS: usize = 200;
/// The most lines one message lists.
const MAX_LINES: usize = 10;

#[derive(Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    config: Config,
    input: Option<Input>,
}

#[derive(Deserialize, Default)]
struct Config {
    /// The message's title.
    #[serde(rename = "TITLE")]
    title: Option<String>,
}

#[derive(Deserialize)]
struct Input {
    #[serde(default)]
    picked: Vec<Picked>,
    #[serde(rename = "__staleness__", default)]
    staleness: Option<Staleness>,
    #[serde(rename = "__degraded_inputs__", default)]
    degraded: Option<Degraded>,
}

#[derive(Deserialize)]
struct Picked {
    #[serde(default)]
    id: String,
    #[serde(default)]
    because: String,
}

#[derive(Deserialize)]
struct Staleness {
    #[serde(default)]
    any_stale: bool,
}

#[derive(Deserialize)]
struct Degraded {
    #[serde(default)]
    any_degraded: bool,
}

#[talos_module(world = "minimal-node")]
pub fn run(input: String) -> Result<String, String> {
    let envelope: Envelope = serde_json::from_str(&input).map_err(|e| format!("Input parse error: {e}"))?;
    let input = envelope.input.ok_or("the input did not arrive")?;
    let title = plain(envelope.config.title.as_deref().unwrap_or("Picked today"), TITLE_CHARS);
    let mut warnings: Vec<String> = Vec::new();
    if input.staleness.is_some_and(|s| s.any_stale) {
        warnings.push("⚠ some of what this is drawn from is out of date".to_string());
    }
    if input.degraded.is_some_and(|d| d.any_degraded) {
        warnings.push("⚠ a source this draws on failed; this may be incomplete".to_string());
    }
    if input.picked.is_empty() && warnings.is_empty() {
        return serde_json::to_string(&json!({ "kind": "skeleton_composer", "skip": true })).map_err(|e| e.to_string());
    }
    // Lines are added while they fit, so the count of what did not fit is never cut off.
    let mut body: Vec<String> = warnings;
    let reserve = "…and 9999 more".chars().count() + 1;
    let mut used: usize = body.iter().map(|l| l.chars().count() + 1).sum();
    let mut shown = 0;
    for p in input.picked.iter().take(MAX_LINES) {
        let line = plain(&format!("{}: {}", p.id, p.because), LINE_CHARS);
        let cost = line.chars().count() + 1;
        if used + cost + reserve > BODY_CHARS {
            break;
        }
        used += cost;
        body.push(line);
        shown += 1;
    }
    if input.picked.len() > shown {
        body.push(format!("…and {} more", input.picked.len() - shown));
    }
    let body = body.join("\n");
    let out = json!({
        "kind": "skeleton_composer",
        "skip": false,
        "notification": { "title": title, "body": body, "priority": "normal", "tag": "skeleton-composer" },
    });
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

/// Text as it may be rendered: no control characters but line breaks, cut to a length.
fn plain(s: &str, max: usize) -> String {
    s.chars().filter(|c| *c == '\n' || !c.is_control()).take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// The envelope the recorded run is made with.
    fn envelope() -> String {
        json!({
            "config": {"TITLE": "Urgent"},
            "input": {"picked": [{"id": "a", "because": "its name holds \"urgent\""}]},
        })
        .to_string()
    }

    fn rendered(e: String) -> Value {
        serde_json::from_str(&run(e).unwrap()).unwrap()
    }

    #[test]
    fn it_renders_what_was_decided_as_a_notification() {
        let out = rendered(envelope());
        assert_eq!(out["notification"], json!({"title": "Urgent", "body": "a: its name holds \"urgent\"", "priority": "normal", "tag": "skeleton-composer"}));
        // This run is the template's recorded run (fixtures/): `make record-template` rewrites it.
        talos_module_testkit::recorded_run::keep("skeleton-composer", &envelope());
    }

    #[test]
    fn nothing_to_say_is_a_skip_and_a_failed_source_is_said() {
        assert_eq!(rendered(json!({"input": {"picked": []}}).to_string())["skip"], json!(true));
        let out = rendered(json!({"input": {"picked": [], "__degraded_inputs__": {"any_degraded": true}}}).to_string());
        assert!(out["notification"]["body"].as_str().unwrap().contains("failed"));
        let out = rendered(json!({"input": {"picked": [{"id": "x", "because": "y"}], "__staleness__": {"any_stale": true}}}).to_string());
        assert!(out["notification"]["body"].as_str().unwrap().starts_with("⚠ some of what"));
    }

    #[test]
    fn its_input_is_made_plain_and_cut_to_the_contracts_lengths() {
        // Fifteen long lines: fewer than ten fit in the body, and the rest are counted, not cut.
        let long: Vec<Value> = (0..15).map(|n| json!({"id": format!("i{n}\u{7}"), "because": "x".repeat(400)})).collect();
        let out = rendered(json!({"config": {"TITLE": "t".repeat(300)}, "input": {"picked": long}}).to_string());
        let n = &out["notification"];
        assert_eq!(n["title"].as_str().unwrap().chars().count(), TITLE_CHARS);
        let body = n["body"].as_str().unwrap();
        assert!(body.chars().count() <= BODY_CHARS && !body.contains('\u{7}') && body.ends_with(" more"));
    }
}
