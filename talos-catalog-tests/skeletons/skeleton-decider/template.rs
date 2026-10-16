// skeleton-decider: computes over its input and calls nothing: no network,
// no memory, no model. Its output says what it decided and enough of why to
// audit it.
//
// TODO(author): say what it decides, from which reader's output. Replace the
// rule (an item is picked when its name holds one of WORDS) with yours.
//
// What this shape already does, and what the catalog's tests hold it to:
// * minimal-node: no host, no verb, no secret (talos.json grants none);
// * deterministic: the same input gives the same output;
// * every input it did not judge is counted (`ignored`), never dropped;
// * input that is not there is an error, not an empty answer.

use serde::Deserialize;
use serde_json::json;
use talos_sdk_macros::talos_module;

/// The most items judged in one run, and the most words matched.
const MAX_ITEMS: usize = 500;
const MAX_WORDS: usize = 20;
const FIELD_CHARS: usize = 200;

#[derive(Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    config: Config,
    input: Option<Input>,
}

#[derive(Deserialize, Default)]
struct Config {
    /// The words that pick an item when its name holds one (matched without
    /// regard to case).
    #[serde(rename = "WORDS")]
    words: Option<Vec<String>>,
}

/// What the upstream node hands on. Only the fields read are parsed.
#[derive(Deserialize)]
struct Input {
    #[serde(default)]
    items: Vec<Item>,
}

#[derive(Deserialize)]
struct Item {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
}

#[talos_module(world = "minimal-node")]
pub fn run(input: String) -> Result<String, String> {
    let envelope: Envelope = serde_json::from_str(&input).map_err(|e| format!("Input parse error: {e}"))?;
    let words: Vec<String> = envelope
        .config
        .words
        .unwrap_or_default()
        .iter()
        .map(|w| w.trim().to_lowercase())
        .filter(|w| !w.is_empty())
        .collect();
    if words.is_empty() || words.len() > MAX_WORDS {
        return Err(format!("WORDS must hold 1 to {MAX_WORDS} words"));
    }
    let input = envelope.input.ok_or("the input did not arrive")?;
    let considered = input.items.len().min(MAX_ITEMS);
    let mut picked = Vec::new();
    for item in input.items.iter().take(MAX_ITEMS) {
        let name = item.name.to_lowercase();
        if let Some(word) = words.iter().find(|w| name.contains(w.as_str())) {
            picked.push(json!({ "id": plain(&item.id), "because": format!("its name holds \"{word}\"") }));
        }
    }
    let out = json!({
        "kind": "skeleton_decider",
        "considered": considered,
        "ignored": input.items.len() - considered,
        "picked": picked,
    });
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

/// Text as it may be handed on: no control characters, cut to a length.
fn plain(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(FIELD_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// The envelope the recorded run is made with.
    fn envelope() -> String {
        json!({
            "config": {"WORDS": ["Urgent"]},
            "input": {"items": [{"id": "a", "name": "Urgent: renew"}, {"id": "b", "name": "Weekly notes"}]},
        })
        .to_string()
    }

    #[test]
    fn it_picks_by_its_rule_and_says_why() {
        let out: Value = serde_json::from_str(&run(envelope()).unwrap()).unwrap();
        assert_eq!(out["picked"], json!([{"id": "a", "because": "its name holds \"urgent\""}]));
        assert_eq!((out["considered"].clone(), out["ignored"].clone()), (json!(2), json!(0)));
        // This run is the template's recorded run (fixtures/): `make record-template` rewrites it.
        talos_module_testkit::recorded_run::keep("skeleton-decider", &envelope());
    }

    #[test]
    fn what_it_did_not_judge_is_counted() {
        let items: Vec<Value> = (0..MAX_ITEMS + 3).map(|n| json!({"id": n.to_string(), "name": "x"})).collect();
        let out: Value = serde_json::from_str(&run(json!({"config": {"WORDS": ["y"]}, "input": {"items": items}}).to_string()).unwrap()).unwrap();
        assert_eq!((out["considered"].clone(), out["ignored"].clone()), (json!(MAX_ITEMS), json!(3)));
    }

    #[test]
    fn missing_input_or_config_is_an_error_not_an_empty_answer() {
        assert_eq!(run(json!({"config": {"WORDS": ["a"]}}).to_string()).unwrap_err(), "the input did not arrive");
        assert!(run(json!({"config": {}, "input": {"items": []}}).to_string()).is_err());
    }
}
